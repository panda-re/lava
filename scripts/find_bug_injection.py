import json
import sys
import ijson
import os
from database_types import AttackPoint, Bug, \
    ASTLoc, DuaBytes, SourceLval, LabelSet, Dua, Range, LavaDatabase, AtpKind, BugKind
from vars import parse_vars
from sqlalchemy.exc import IntegrityError
from typing import Iterable, TypeVar, DefaultDict, Set
from collections import defaultdict
import random
from sqlalchemy import select
from sqlalchemy.orm import Session
from bisect import bisect_left

T = TypeVar("T")

# These map pointer values in the PANDA taint run to the sets they refer to.
ptr_to_labelset: dict[int, LabelSet] = {}

# Map from label to duas that are tainted by that label.
# So when we update liveness, we know what duas might be invalidated.
dua_dependencies: DefaultDict[int, Set[Dua]] = defaultdict(set)

# Liveness for each input byte.
liveness: DefaultDict[int, int] = defaultdict(int)

CBNO_TCN_BIT: int = 0
CBNO_CRD_BIT: int = 1
CBNO_LVN_BIT: int = 2

# number of bytes in lava magic value used to trigger bugs
LAVA_MAGIC_VALUE_SIZE: int = 4
# special flag to indicate untainted byte that we want to use for fake dua
FAKE_DUA_BYTE_FLAG: int = 777

# List of recent duas sorted by dua->instr. Invariant should hold that:
recent_duas_by_instr: list[Dua] = []
# set(recent_dead_duas.values()) == set(recent_duas_by_instr).
# Map from source lval ID to most recent DUA incarnation.
recent_dead_duas: dict[int, Dua] = {}

num_real_duas : int = 0
num_fake_duas : int = 0
num_bugs_added_to_db : int = 0
num_potential_bugs : int = 0
num_potential_nonbugs : int = 0
num_bugs_of_type: defaultdict[BugKind, int] = defaultdict(int)

def dprint(project_data: dict, message: str):
    if project_data.get("debug", True):
        print(message)


def disjoint(iter1: Iterable[T], iter2: Iterable[T]) -> bool:
    """
    Return True if the two sorted iterables have no element in common.
    Both iterables must be sorted in ascending order.
    """
    it1 = iter(iter1)
    it2 = iter(iter2)

    try:
        a = next(it1)
    except StopIteration:
        return True
    try:
        b = next(it2)
    except StopIteration:
        return True

    while True:
        if a < b:
            try:
                a = next(it1)
            except StopIteration:
                return True
        elif b < a:
            try:
                b = next(it2)
            except StopIteration:
                return True
        else:
            # a == b -> not disjoint
            return False


def disjoint_dua(db1: DuaBytes, db2: DuaBytes) -> bool:
    """
    Expect objects with an `all_labels` attribute (an iterable of sorted labels).
    Mirrors the C++ overload that uses `db->all_labels`.
    """
    return disjoint(getattr(db1, "all_labels"), getattr(db2, "all_labels"))


def count_nonzero(arr: Iterable[LabelSet]) -> int:
    """
    Return number of elements in `arr` that are not zero.
    """
    return sum(1 for t in arr if t.labels != 0)


def merge_into(source_elements: list, dest_list: list):
    """
    Performs a set union of dest_list and source_elements, ensuring the result
    is sorted and unique, updating dest_list in-place.
    """
    # 1. set(dest_list) creates a set from the current list
    # 2. .union(source_elements) adds the new items, handling deduping
    # 3. sorted() turns it back into a sorted list
    # 4. dest_list[:] = ... replaces the contents in-place (no new object created)
    dest_list[:] = sorted(set(dest_list).union(source_elements))


# Assuming you have these imported
# from .models import Bug, BugKind, AttackPoint, AtpKind, DuaBytes, Dua
# from .utils import get_or_create, merge_into, disjoint, get_dua_dead_range

def record_injectable_bugs_at(bug_type: BugKind, atp: AttackPoint, is_new_atp: bool,
                              session: Session, extra_duas_prechosen: list[DuaBytes], project_data: dict):
    """
    Record injectable bugs at a given attack point (atp) of a given type (bug_type).
    """
    skip_trigger_lval_ids = []

    # --- 1. THE ODB REPLACEMENT ---
    if not is_new_atp:
        # In C++, this query was cached. In Python/Postgres, just run it.
        # We want to find all 'trigger_lval_id's that successfully generated
        # a bug for this specific ATP and BUG TYPE.
        stmt = select(Bug.trigger_lval_id).where(
            Bug.atp_id == atp.id,
            Bug.type == bug_type
        )
        # scalars() extracts the single value from the row automatically
        # This returns a clean List[int] that the IDE understands perfectly
        skip_trigger_lval_ids = sorted(session.scalars(stmt).all())

    skip_it = 0

    # --- 2. Fix Bug Metadata Access ---
    # Use the dictionary we defined in the Bug class
    required_extra = Bug.required_extra_duas_for_type[bug_type]
    num_extra_duas = required_extra - len(extra_duas_prechosen)
    assert num_extra_duas >= 0

    prechosen_labels : list[int] = []
    for extra in extra_duas_prechosen:
        merge_into(extra.all_labels, prechosen_labels)

    # Loop over recent_dead_duas (Dict: lval_id -> Dua object)
    for lval_id, trigger_dua in recent_dead_duas.items():

        # --- 3. The Skip Logic (Linear Scan on Sorted Lists) ---
        # Fast-forward skip_it so it matches or exceeds current lval_id
        while skip_it < len(skip_trigger_lval_ids) and skip_trigger_lval_ids[skip_it] < lval_id:
            skip_it += 1

        # If we found a match, this LVAL + ATP + TYPE combo has been done. Skip.
        if skip_it < len(skip_trigger_lval_ids) and skip_trigger_lval_ids[skip_it] == lval_id:
            continue

        # --- 4. Range Logic ---
        selected : Range = get_dua_dead_range(trigger_dua, prechosen_labels, project_data)
        # Ensure LAVA_MAGIC_VALUE_SIZE is defined/imported
        if selected.empty() or selected.size() < LAVA_MAGIC_VALUE_SIZE:
            continue

        # --- 5. Fix get_or_create for DuaBytes ---
        # Assuming DuaBytes takes 'dua' and 'selected_range' columns
        trigger_duabytes, _ = get_or_create(
            session,
            DuaBytes,
            dua=trigger_dua,
            selected=selected
        )

        extra_duas = list(extra_duas_prechosen)
        labels_so_far = list(prechosen_labels)
        merge_into(trigger_duabytes.all_labels, labels_so_far)

        # --- 6. Fix "lower_bound" (Performance) ---
        # C++ std::lower_bound is Binary Search.
        # Python 'next(...)' is Linear Search (Slow!).
        # We use bisect_left on 'recent_duas_by_instr'.
        # Since recent_duas_by_instr contains objects, we need a key.
        # Python 3.10+ supports key in bisect.

        # Find index where dua.instr >= trigger_dua.instr
        end_idx = bisect_left(
            recent_duas_by_instr,
            trigger_dua.instr,
            key=lambda d: d.instr
        )

        begin_idx = 0
        distance = end_idx - begin_idx

        if num_extra_duas < distance:
            for _ in range(num_extra_duas):
                extra = None
                for tries in range(2):
                    # Random index in range
                    idx = random.randint(begin_idx, end_idx - 1)
                    extra_dua = recent_duas_by_instr[idx]

                    selected_extra : Range = get_dua_dead_range(extra_dua, labels_so_far, project_data)
                    if selected_extra.empty():
                        continue

                    extra, _ = get_or_create(
                        session,
                        DuaBytes,
                        dua=extra_dua,
                        selected=selected_extra
                    )

                    if disjoint(labels_so_far, extra.all_labels):
                        break

                if extra is None:
                    break  # Failed to find a disjoint extra dua

                extra_duas.append(extra)
                # merge_into modifies labels_so_far in place
                merge_into(extra.all_labels, labels_so_far)

        if len(extra_duas) < required_extra:
            continue

        if not trigger_duabytes.dua.fake_dua:
            if not (len(labels_so_far) >= 4 * required_extra):
                continue

        # Calculate max liveness
        c_max_liveness = 0
        for l in trigger_duabytes.all_labels:
            c_max_liveness = max(c_max_liveness, liveness[l])

        # Assertions
        assert bug_type != BugKind.BUG_RET_BUFFER or atp.type == AtpKind.QUERY_POINT
        assert len(extra_duas) == required_extra

        # --- 7. Save Bug ---
        # The Bug Model expects 'extra_duas' to be a LIST OF IDs (Array[BigInt]),
        # not a list of objects. We extract .id here.
        extra_duas_ids = [d.id for d in extra_duas]

        bug = Bug(
            bug_type=bug_type,
            trigger=trigger_duabytes,
            max_liveness=c_max_liveness,
            atp=atp,
            extra_duas=extra_duas_ids
        )

        session.add(bug)  # SQLAlchemy's version of persist()

        # --- 8. Update Globals ---
        # Ensure these are declared global if you are modifying them
        global num_bugs_added_to_db, num_potential_bugs, num_potential_nonbugs
        num_bugs_of_type[bug_type] += 1
        num_bugs_added_to_db += 1

        if trigger_dua.fake_dua:
            num_potential_nonbugs += 1
        else:
            num_potential_bugs += 1


def attack_point_lval_usage(ple: dict, session: Session, ind2str: dict[int, str], project_data: dict):
    """
    Process an attack point log entry from PANDA logs.
    Args:
        ple (dict): The AttackPoint PANDA Log Entry
        session (Session): The Database connection to input Attack Point data
        ind2str: a list mapping indices to strings from lavadb. This obtains the filename from a number.
        project_data: a dict of input values
    """
    panda_log_entry_attack_point = ple["attackPoint"]
    ast_id = None

    if "astLocId" in panda_log_entry_attack_point["srcInfo"]:
        ast_id = int(panda_log_entry_attack_point["srcInfo"]["astLocId"])
        dprint(project_data, f"attack point id = {ast_id}")

    source_info = panda_log_entry_attack_point["srcInfo"]
    # ignore duas in header files
    # Remember, in PandaLog, AttackPoint filenames are numbers!
    if is_header_file(ind2str[ast_id]):
        return

    dprint(project_data, "ATTACK POINT")
    if len(recent_dead_duas) == 0:
        dprint(project_data, "no duas yet -- discarding attack point")
        return

    dprint(project_data, f"{len(recent_dead_duas)} viable duas remain")
    assert "astLocId" in source_info
    ast_loc = ASTLoc.from_serialized(ind2str[ast_id])
    assert len(ast_loc.filename) > 0
    attack_point_type = panda_log_entry_attack_point["info"]

    atp, is_new_atp = get_or_create(
        session,
        AttackPoint,
        loc=ast_loc,
        type=attack_point_type
    )

    dprint(project_data, f"@ATP: {str(atp)}")

    # Don't decimate PTR_ADD bugs.
    if attack_point_type == AtpKind.POINTER_WRITE:
        record_injectable_bugs_at(BugKind.BUG_REL_WRITE, atp, is_new_atp, session, [], project_data)
    if attack_point_type in [AtpKind.POINTER_READ, AtpKind.FUNCTION_CALL]:
        record_injectable_bugs_at(BugKind.BUG_PTR_ADD, atp, is_new_atp, session, [], project_data)
    elif attack_point_type == AtpKind.PRINTF_LEAK:
        record_injectable_bugs_at(BugKind.BUG_PRINTF_LEAK, atp, is_new_atp, session, [], project_data)
    elif attack_point_type == AtpKind.MALLOC_OFF_BY_ONE:
        record_injectable_bugs_at(BugKind.BUG_MALLOC_OFF_BY_ONE, atp, is_new_atp, session, [], project_data)


def get_dua_exploit_pad(dua: Dua) -> Range:
    """
    Scans the DUA's viable bytes to find the largest contiguous run of
    'clean' bytes (tainted, uncomplicated, dead) suitable for exploitation.
    """
    current_run = Range(0, 0)
    largest_run = Range(0, 0)

    # Iterate through all viable bytes in the DUA
    # Note: verify dua.viable_bytes is a list of LabelSets (or None)
    for i, label_set in enumerate(dua.viable_bytes):

        # Condition Check:
        # 1. ls exists (is tainted)
        # 2. ls has exactly 1 label (uncomplicated taint)
        # 3. Taint Compute Number is 0 (direct copy, not arithmetic result)
        # 4. Liveness is low (label is not used much downstream)
        is_candidate = False
        if label_set is not None and len(label_set.labels) == 1:
            # Get the single label
            label = label_set.labels[0]
            if dua.byte_tcn[i] == 0 and liveness[label] <= 10:
                is_candidate = True

        if is_candidate:
            if current_run.empty():
                current_run = Range(i, i + 1)
            else:
                current_run.high += 1
        else:
            # End of a run, check if it's the new record
            if current_run.size() > largest_run.size():
                largest_run = current_run
            # Reset
            current_run = Range(0, 0)

    # Final check in case the run goes to the very end of the byte array
    if current_run.size() > largest_run.size():
        largest_run = current_run

    # Reserve 4 bytes for trigger at start if the run is substantial
    if largest_run.size() >= 20:
        largest_run.low += 4

    return largest_run


def decimate(ratio: float) -> bool:
    """
    Returns True with probability 1/ratio.
    Examples:
        ratio=1.0 -> 100% True (Keep everything)
        ratio=2.0 -> 50% True (Keep half)
        ratio=100.0 -> 1% True (Keep 1 in 100)
    """
    if ratio <= 0:
        return True  # Safety fallback, though logic dictates ratio >= 1.0

    # random.random() returns [0.0, 1.0)
    return random.random() < (1.0 / ratio)


def decimation_ratio(bug_type: BugKind, potential: int) -> float:
    """
    Calculates a throttling ratio to ensure the database doesn't get flooded
    with one specific type of bug.

    Logic:
    If a bug type is >10,000 counts above the average, we start returning
    a high ratio (e.g., 20.0, 100.0) to aggressively skip new ones.
    """
    num_types_injected_already = 0

    # Iterate over the Enum members directly (Cleaner than C++ for loop)
    for kind in BugKind:
        if num_bugs_of_type[kind] > 0:
            num_types_injected_already += 1

    # Avoid division by zero if DB is empty
    if num_types_injected_already == 0:
        return 1.0

    average_num_bugs = num_bugs_added_to_db / num_types_injected_already

    # How far above the average is this specific bug type?
    current_count = num_bugs_of_type[bug_type]
    diff = (current_count + potential) - average_num_bugs

    # Threshold: If we are within 10,000 of the average, don't throttle (Ratio 1.0).
    if diff < 10000:
        return 1.0
    else:
        # Scale up the ratio: For every bug above the limit, increase rejection chance.
        return 1.0 + (diff - 10000) * 0.2


def decimate_by_type(bug_type: BugKind) -> bool:
    """
    Determines if we should skip this bug based on the decimation ratio.
    """
    # Assuming decimate() and decimation_ratio() are defined helper functions
    return decimate(decimation_ratio(bug_type, 1))


# Assuming globals/constants are available:
# max_lval, LAVA_MAGIC_VALUE_SIZE, max_tcn, max_card, ptr_to_labelset
# dua_dependencies, recent_dead_duas, recent_duas_by_instr
# num_real_duas, num_fake_duas, chaff_bugs, FAKE_DUA_BYTE_FLAG

def taint_query_pri(ple: dict, session: Session, ind2str: dict[int, str], project_data: dict):
    """
    Process a Taint Query Priority entry to identify potential DUAs (Dead Unused Available).
    """
    taint_query_header = ple["taintQueryPri"]

    # 1. Parse Header Info
    # std::min logic: Cap the length at max_lval
    raw_len = int(taint_query_header["len"])
    length = min(raw_len, project_data["max_lval_size"])
    num_tainted = int(taint_query_header["numTainted"])

    source_info = taint_query_header["srcInfo"]
    filename = str(source_info["filename"])

    # Ignore headers
    if is_header_file(filename):
        return

    instr_addr = int(ple["instr"])
    dprint(project_data, f"TAINT QUERY HYPERCALL len={length} num_tainted={num_tainted}")

    # 2. Collect Labels & Unique Sets
    all_labels = set()  # Using set for O(1) uniqueness, sorted list later if needed

    # We maintain max stats for this specific DUA
    c_max_tcn = 0
    c_max_card = 0

    # Process new unique label sets from the log
    for taint_query in taint_query_header["taintQuery"]:
        if "uniqueLabelSet" in taint_query:
            update_unique_taint_sets(taint_query["uniqueLabelSet"], project_data)

    # 3. Viability Analysis (Real DUA)
    # Initialize arrays of size 'length'
    viable_byte: list[LabelSet | None] = [None] * length
    byte_tcn = [0] * length

    dprint(project_data,f"considering taint queries on {num_tainted} bytes\n")
    is_dua = False
    is_fake_dua = False
    num_viable_bytes = 0

    # Optimization: Don't check if we don't have enough tainted bytes
    if num_tainted >= LAVA_MAGIC_VALUE_SIZE:
        for taint_query in taint_query_header["taintQuery"]:
            offset = int(taint_query["offset"])
            if offset >= length:
                continue
            dprint(project_data,f"considering offset = {offset}")
            ptr = int(taint_query["ptr"])
            tcn = int(taint_query["tcn"])

            # Retrieve the LabelSet object from our global map
            label_set = ptr_to_labelset.get(ptr)
            if not label_set:
                continue

            byte_tcn[offset] = tcn

            # Filtering Logic (Bitwise logic simplified to boolean)
            tcn_too_high = tcn > project_data["max_tcn"]
            # Note: ls.labels is a list/array
            card_too_high = len(label_set.labels) > project_data["max_cardinality"]

            if tcn_too_high or card_too_high:
                dprint(project_data, f"discarding byte {offset}: tcn={tcn_too_high} card={card_too_high}")
            else:
                # Retain byte
                c_max_tcn = max(tcn, c_max_tcn)
                c_max_card = max(len(label_set.labels), c_max_card)

                # Merge labels (Python set update handles deduping)
                all_labels.update(label_set.labels)
                dprint(project_data, f"keeping byte @ offset {offset}")

                viable_byte[offset] = label_set
                num_viable_bytes += 1

        dprint(project_data, "{num_viable_bytes} viable bytes in lval")

        # Check DUA Viability
        # 1. Enough viable bytes
        # 2. Enough total labels involved
        # 3. Enough dead bytes (ranges)
        if (num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE and
                len(all_labels) >= LAVA_MAGIC_VALUE_SIZE):

            # get_dead_range expects a list of LabelSets (or None)
            # We assume get_dead_range returns a Range object with a .size property
            dead_range = get_dead_range(viable_byte, [], project_data)
            if dead_range.size() >= LAVA_MAGIC_VALUE_SIZE:
                is_dua = True

    # 4. Fake DUA Logic (The Fix)
    # If we are making chaff bugs, it's not a real DUA, and we have enough empty space
    if (not is_dua and
            (raw_len - num_tainted) >= LAVA_MAGIC_VALUE_SIZE):

        dprint(project_data, "not enough taint -- what about non-taint?")
        dprint(project_data, f"len={length} num_tainted={num_tainted}")

        # Reset viable_byte to clean slate for fake generation
        viable_byte = [None] * length

        # Get the Singleton Fake LabelSet (Get or Create)
        # 0xFA4E is a magic number often used for fake flags
        fake_ls, _ = get_or_create(
            session,
            LabelSet,
            ptr=FAKE_DUA_BYTE_FLAG,
            inputfile="fakedua",
            labels=[]
        )

        count = 0
        # 'i' starts at 0 and increments every time we look at a taint query
        # This matches the C++ loop where ++i happens at the bottom of every iteration
        for i, taint_query in enumerate(taint_query_header["taintQuery"]):
            offset = int(taint_query["offset"])

            # C++: if (offset > i)
            # If the tainted byte is further ahead than our current index,
            # it means index 'i' is untainted and available for a fake DUA.
            if offset > i:
                viable_byte[i] = fake_ls
                count += 1

            # Stop as soon as we have enough bytes for a LAVA magic value
            if count >= LAVA_MAGIC_VALUE_SIZE:
                break

        if count >= LAVA_MAGIC_VALUE_SIZE:
            is_fake_dua = True

    # 5. Database Persistence & Registration
    dprint(project_data, f"is_dua={is_dua} is_fake_dua={is_fake_dua}")
    assert not (is_dua and is_fake_dua)

    if is_dua or is_fake_dua:
        assert "astLocId" in source_info
        ast_loc_id = int(source_info["astLocId"])

        # Create ASTLoc object
        ast_loc = ASTLoc.from_serialized(ind2str[ast_loc_id])
        assert len(ast_loc.filename) > 0

        # Create SourceLval
        lval, _ = get_or_create(
            session,
            SourceLval,
            loc=ast_loc,
            ast_name=str(source_info["astnodename"]),
            len_bytes=length
        )

        # Create Dua
        # Note: all_labels is a set, convert to sorted list for DB array
        sorted_labels = sorted(list(all_labels))
        dua, is_new_dua = get_or_create(
            session,
            Dua,
            lval=lval,
            inputfile="unknown",
            instr=instr_addr,
            fake_dua=is_fake_dua,

            # --- DATA PAYLOAD (Only used if creating a NEW entry) ---
            defaults={
                'viable_bytes': [vb for vb in viable_byte if vb is not None],
                'byte_tcn': byte_tcn,
                'all_labels': sorted_labels,
                'max_tcn': c_max_tcn,
                'max_cardinality': c_max_card
            }
        )

        # Track Dependencies
        if is_dua:
            for l in sorted_labels:
                dua_dependencies[l].add(dua)

        # Handle Buffer Overflow Injection (RET_BUFFER)
        # Create AttackPoint (QUERY_POINT)
        pad_atp, is_new_atp = get_or_create(
            session,
            AttackPoint,
            loc=ast_loc,
            type=AtpKind.QUERY_POINT
        )

        if length >= 20 and decimate_by_type(BugKind.BUG_RET_BUFFER):
            exploit_range = get_dua_exploit_pad(dua)

            # create(DuaBytes...)
            dua_bytes, _ = get_or_create(
                session,
                DuaBytes,
                dua=dua,
                selected=exploit_range
            )

            if is_fake_dua or exploit_range.size() >= 20:
                record_injectable_bugs_at(
                    BugKind.BUG_RET_BUFFER,
                    pad_atp,
                    is_new_atp,
                    session,
                    [dua_bytes],
                    project_data
                )
        dprint(project_data, "OK DUA.")

        # 6. Global State Maintenance (recent_dead_duas)
        # Logic: Replace old DUA with same lval_id, or insert new.

        lval_id = lval.id

        if lval_id in recent_dead_duas:
            # We have seen this LVAL before. Replace it.
            old_dua = recent_dead_duas[lval_id]

            # Remove from recent_duas_by_instr
            # Note: Python list.remove is O(N). If this list is huge,
            # we might need a better structure, but recent window is usually small-ish.
            try:
                recent_duas_by_instr.remove(old_dua)
            except ValueError:
                pass  # Should ideally not happen based on C++ logic assertions

            # Clean up old dependencies
            for l in old_dua.all_labels:
                if old_dua in dua_dependencies[l]:
                    dua_dependencies[l].remove(old_dua)

            dprint(project_data,"previously observed lval")
        else:
            dprint(project_data, "new lval")

        # Insert/Update the map
        recent_dead_duas[lval_id] = dua

        # Enforce sorted order logic for recent_duas_by_instr
        # C++ did: assert(dua->instr >= recent_duas_by_instr.back()->instr);
        # This implies the log is processed in execution order, so we can just append.
        recent_duas_by_instr.append(dua)

        # Verify invariants
        assert len(recent_dead_duas) == len(recent_duas_by_instr)

        # 7. Update Stats (Global)
        global num_real_duas, num_fake_duas
        if is_dua:
            num_real_duas += 1
        if is_fake_dua:
            num_fake_duas += 1
    else:
        # Debugging discard
        filename = source_info["filename"]
        line_number = source_info["linenum"]
        ast_node_name = source_info["astnodename"]
        dprint(project_data, f"discarded {num_viable_bytes} viable bytes {len(all_labels)} labels"
                             f"{filename}:{line_number} {ast_node_name}")


def get_or_create(session: Session, model, defaults: dict=None, **kwargs):
    """
    Retrieves object or creates it using an EXISTING session.
    Args:
        session: The SQLAlchemy session to use.
        model: The SQLAlchemy model class.
        defaults: A dict of default values to use when creating the object.
        **kwargs: The lookup parameters.
    """
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance, False
    else:
        params = {**kwargs, **(defaults or {})}
        instance = model(**params)
        session.add(instance)
        try:
            # We commit here to generate the ID (if auto-incrementing)
            # and handle the race condition safely.
            session.commit()
            return instance, True
        except IntegrityError:
            session.rollback()
            instance = session.query(model).filter_by(**kwargs).first()
            if instance:
                return instance, False
            else:
                raise


def update_unique_taint_sets(unique_label_set: dict, project_data: dict):
    """
    Update the global mapping of unique taint sets based on the provided unique_label_set from PANDA Log.
    Args:
        unique_label_set (dict): the Panda Log unique label set
        project_data (dict): Lava project parameters
    """
    dprint(project_data, "UNIQUE TAINT SET")
    dprint(project_data, json.dumps(unique_label_set))
    pointer = int(unique_label_set["ptr"])

    # The Lookup Logic (Major Fix)
    # C++ was checking if the pointer existed.
    # Python dicts are Hash Maps. Lookups are O(1).
    if pointer not in ptr_to_labelset:
        # Ensure labels are integers (C++ did a conversion)
        labels = [int(x) for x in unique_label_set["label"]]

        # 3. Create LabelSet and append to global map
        label_set = LabelSet(
            ptr=pointer,
            inputfile="unknown",
            labels=labels
        )
        ptr_to_labelset[pointer] = label_set
    dprint(project_data, f"{len(ptr_to_labelset)} unique taint sets\n")


def update_liveness(panda_log_entry: dict, project_data: dict):
    """
    Processes a 'taintedBranch' entry from PANDA logs to update global liveness state
    and prune non-viable Def-Use Associations (DUAs).

    This function performs three main steps:
    1.  **Label Aggregation:** Iterates through all taint queries in the branch entry,
        updates the global `ptr_to_labelset` map via `update_unique_taint_sets`,
        and merges all discovered labels into a single sorted list (`all_labels`).
    2.  **Liveness Updates:** Increments the liveness count for every label found.
        It identifies potential candidate DUAs to check by looking up dependencies
        (`dua_dependencies`) associated with these labels.
    3.  **Viability Check:** Verifies if the candidate DUAs are still "dead" (viable for injection).
        If a DUA is found to be alive (i.e., `!is_dua_dead`), it is marked non-viable
        and removed from `recent_dead_duas`, `recent_duas_by_instr`, and the
        dependency tracking maps.

    Args:
        panda_log_entry (dict): The parsed JSON entry containing a "taintedBranch" object.
        project_data (dict): Configuration data for viability checks.

    Side Effects:
        - Modifies global `liveness` (increments counts).
        - Modifies global `recent_dead_duas` and `recent_duas_by_instr` (removes items).
        - Modifies global `dua_dependencies` (removes items).
        - Updates the database (via `update_unique_taint_sets`).
    """
    assert panda_log_entry is not None
    tainted_branch = panda_log_entry["taintedBranch"]
    dprint(project_data, "TAINTED BRANCH")
    assert tainted_branch is not None

    all_labels = []
    for taint_query in tainted_branch["taintQuery"]:
        assert taint_query
        if "uniqueLabelSet" in taint_query:
            # This will be updating the database with new LabelSets as needed
            update_unique_taint_sets(taint_query["uniqueLabelSet"], project_data)
        pointer = int(taint_query["ptr"])
        cur_labels = ptr_to_labelset[pointer].labels
        merge_into(cur_labels, all_labels)

    duas_to_check = []
    for label in all_labels:
        liveness[label] += 1
        dprint(project_data, f"checking viability of {len(recent_dead_duas)} duas")
        depends = dua_dependencies.get(label)
        if depends:
            if isinstance(depends, list) or isinstance(depends, set):
                merge_into(depends, duas_to_check)
            else:
                merge_into([depends], duas_to_check)

    non_viable_duas = []
    for dua in duas_to_check:
        if not is_dua_dead(dua, project_data):
            dprint(project_data, f"{str(dua)}\n ** DUA not viable\n")
            recent_dead_duas.pop(dua.lval.id, None)
            if dua in recent_duas_by_instr:
                recent_duas_by_instr.remove(dua)
            assert len(recent_dead_duas) == len(recent_duas_by_instr)
            non_viable_duas.append(dua)

    dprint(project_data, f"{len(non_viable_duas)} non-viable duas \n")
    for dua in non_viable_duas:
        for label in dua.all_labels:
            if label in dua_dependencies:
                dua_dependencies.pop(label, None)


def is_dua_dead(dua: Dua, project_data: dict) -> bool:
    return get_dua_dead_range(dua, [], project_data).size() == LAVA_MAGIC_VALUE_SIZE


def get_dua_dead_range(dua: Dua, to_avoid: list[int], project_data: dict) -> Range:
    viable_bytes = dua.viable_bytes
    dprint(project_data, f"checking viability of dua: currently {count_nonzero(viable_bytes)} viable bytes")
    if "nodua" in dua.lval.ast_name:
        dprint(project_data, f"Found nodua symbol, skipping {dua.lval.ast_name}")
        empty = Range(0, 0)
        return empty
    result = get_dead_range(dua.viable_bytes, to_avoid, project_data)
    dprint(project_data, f"{dua}\ndua has {result.size()} viable bytes")
    return result


# get first 4-or-larger dead range. to_avoid is a sorted vector of labels that
# can't be used
def get_dead_range(viable_bytes: list[LabelSet], to_avoid: list[int], project_data: dict) -> Range:
    current_run = Range(0, 0)
    # NB: we have already checked dua for viability wrt tcn & card at induction
    # these do not need re-checking as they are to be captured at dua siphon point
    for i in range(len(viable_bytes)):
        byte_viable = True
        label_set = viable_bytes[i]
        if label_set:
            if not disjoint(label_set.labels, to_avoid):
                byte_viable = False
            else:
                for label in label_set.labels:
                    if liveness[label] > project_data["max_liveness"]:
                        dprint(project_data, f"byte offset is nonviable b/c label {label} has liveness {liveness[label]}")
                        byte_viable = False
                        break
            if byte_viable:
                if current_run.empty():
                    current_run = Range(i, i + 1)
                else:
                    current_run.high += 1
                    if current_run.size() >= LAVA_MAGIC_VALUE_SIZE:
                        break
                continue
        current_run = Range(0, 0)
    if current_run.size() < LAVA_MAGIC_VALUE_SIZE:
        return Range(0, 0)
    return current_run


def record_call(ple: dict):
    """
    Record a Dwarf2 call from Panda Log
    Args:
        ple: Pandalog entry
    """
    pass


def record_ret(ple: dict):
    """
    Record a Dwarf2 call from Panda Log
    Args:
        ple: Pandalog entry
    """
    pass


def is_header_file(filename: str) -> bool:
    """
    Return true if filename ends with .h
    Args:
        filename: Filename to check
    Returns:
        bool: True if filename ends with .h
    """
    return filename[-2] == '.' and filename[-1] == 'h'


def load_db(db_file: str) -> dict[int, str]:
    string_ids = {}

    with open(db_file, 'r', encoding='utf-8', errors='replace') as f:
        for line in f:
            # 1. Clean up the line (removes the trailing \n)
            line = line.strip()
            if not line:
                continue

            parts = line.split('\t', 1)
            if len(parts) == 2:
                try:
                    # parts[0] is the ID ("3"), parts[1] is the Value ("toy.c:...")
                    string_ids[int(parts[0])] = parts[1]
                except ValueError:
                    continue  # Skip lines with bad IDs

    return string_ids


def parse_panda_log(panda_log_file: str, project_data: dict):
    """
    Main function for Find Bug Inject (FBI) tool.
    """
    # maps from ind -> (filename, lvalname, attackpointname)
    root_directory = project_data["output_dir"]
    lavadb = f"{root_directory}/lavadb"
    lava_db = load_db(lavadb)
    print(f"{len(lava_db)} strings in lavadb")

    pguser = os.getenv("POSTGRES_USER")
    pgpass = os.getenv("POSTGRES_PASSWORD")
    if pgpass:
        print("POSTGRES_PASSWORD IS SET")
    else:
        print("POSTGRES_PASSWORD is not set")
        sys.exit(1)

    if pguser:
        print(f"POSTGRES_USER IS SET: {pguser}")
    else:
        print("POSTGRES_USER is not set")
        sys.exit(1)

    num_entries_read = 0

    # We want decimation to be deterministic, so srand with magic value.
    random.seed(0x6c617661)

    with open(panda_log_file, 'r') as plog_file:
        # 'item' iterates over elements in the root array
        parser = ijson.items(plog_file, 'item')

        with LavaDatabase(project_data) as db:
            for ple in parser:
                num_entries_read += 1
                if num_entries_read % 10000 == 0:
                    print(f"processed {num_entries_read} pandalog entries")
                    print(f"{num_bugs_added_to_db} added to db {len(recent_dead_duas)} current duas {num_real_duas} real duas {num_fake_duas} fake duas")

                if "taintQueryPri" in ple:
                    taint_query_pri(ple, db.session, lava_db, project_data)
                elif "taintedBranch" in ple:
                    update_liveness(ple, project_data)
                elif "attackPoint" in ple:
                    attack_point_lval_usage(ple, db.session, lava_db, project_data)
                elif "dwarfCall" in ple:
                    record_call(ple)
                elif "dwarfRet" in ple:
                    record_ret(ple)

                if 0 < project_data.get("curtail", 0) < num_real_duas:
                    print(f"*** Curtailing output of fbi at {num_real_duas}")
                    break

    if num_potential_bugs == 0:
        print("No bugs found", file=sys.stderr)
        raise RuntimeError("No bugs found by FBI")
    print_bug_stats(project_data)


def print_bug_stats(project_data: dict):
    with LavaDatabase(project_data) as db:
        print("Count\tBug Type Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))

        print("total dua:", db.session.query(Dua).count())
        print("total atp:", db.session.query(AttackPoint).count())
        print("total bug:", db.session.query(Bug).count())


if __name__ == "__main__":
    host_json = sys.argv[1]
    project_name = sys.argv[2]
    panda_log = sys.argv[3]

    # host_json reads overall config from host.json, project_name finds configs for specific project
    project = parse_vars(host_json, project_name)

    if "max_liveness" not in project:
        print("max_liveness not set, using default 100000")
        project["max_liveness"] = 100000

    # Throw exception if we can't process any required argument
    if not isinstance(project["max_liveness"], int):
        raise RuntimeError("Could not parse max_liveness")

    if "max_cardinality" not in project:
        print("max_cardinality not set, using default 100")
        project["max_cardinality"] = 100
    if not isinstance(project["max_cardinality"], int):
        raise RuntimeError("Could not parse max_cardinality")

    if "max_tcn" not in project:
        print("max_tcn not set, using default 100")
        project["max_tcn"] = 100
    if not isinstance(project["max_tcn"], int):
        raise RuntimeError("Could not parse max_tcn")

    if "max_lval_size" not in project:
        print("max_lval_size not set, using default 100")
        project["max_lval_size"] = 100
    if not isinstance(project["max_lval_size"], int):
        raise RuntimeError("Could not parse max_lval_size")

    if "curtail" not in project:
        print("max_lval_size not set, using default 0")
        project["curtail"] = 0
    if not isinstance(project["curtail"], int):
        raise RuntimeError("Could not parse curtail")

    from dotenv import load_dotenv
    load_dotenv()
    parse_panda_log(panda_log, project)

