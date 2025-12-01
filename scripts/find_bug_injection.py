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

# Map from source lval ID to most recent DUA incarnation.
recent_dead_duas: dict[int, Dua] = {}

# These map pointer values in the PANDA taint run to the sets they refer to.
ptr_to_labelset: dict[int, LabelSet] = {}

# Map from label to duas that are tainted by that label.
# So when we update liveness, we know what duas might be invalidated.
dua_dependencies: DefaultDict[int, Set[Dua]] = defaultdict(set)

# Liveness for each input byte.
liveness: DefaultDict[int, int] = defaultdict(int)

CBNO_TCN_BIT = 0
CBNO_CRD_BIT = 1
CBNO_LVN_BIT = 2
max_lval = 0

# number of bytes in lava magic value used to trigger bugs
LAVA_MAGIC_VALUE_SIZE = 4
# special flag to indicate untainted byte that we want to use for fake dua
FAKE_DUA_BYTE_FLAG = 777

# List of recent duas sorted by dua->instr. Invariant should hold that:
# set(recent_dead_duas.values()) == set(recent_duas_by_instr).
recent_duas_by_instr: list[Dua] = []

num_real_duas, num_fake_duas = 0, 0
num_bugs_added_to_db, num_potential_bugs, num_potential_nonbugs = 0, 0, 0

num_bugs_of_type: dict = { Bug.type : 0 }

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


def count_nonzero(arr: Iterable[int]) -> int:
    """
    Return number of elements in `arr` that are not zero.
    """
    return sum(1 for t in arr if t != 0)


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
                              session: Session, extra_duas_prechosen: list, project: dict):
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
    req_extra = Bug.required_extra_duas_for_type[bug_type]
    num_extra_duas_needed = req_extra - len(extra_duas_prechosen)
    assert num_extra_duas_needed >= 0

    prechosen_labels = []
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
        selected = get_dua_dead_range(trigger_dua, prechosen_labels, project)
        # Ensure LAVA_MAGIC_VALUE_SIZE is defined/imported
        if not selected or selected.size() < LAVA_MAGIC_VALUE_SIZE:
            continue

        # --- 5. Fix get_or_create for DuaBytes ---
        # Assuming DuaBytes takes 'dua' and 'selected_range' columns
        trigger_duabytes, _ = get_or_create(
            session,
            DuaBytes,
            dua=trigger_dua,
            selected_range=selected
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

        if num_extra_duas_needed < distance:
            for _ in range(num_extra_duas_needed):
                extra = None
                for tries in range(2):
                    # Random index in range
                    idx = random.randint(begin_idx, end_idx - 1)
                    extra_dua = recent_duas_by_instr[idx]

                    selected_extra = get_dua_dead_range(extra_dua, labels_so_far)
                    if not selected_extra:
                        continue

                    extra_obj, _ = get_or_create(
                        session,
                        DuaBytes,
                        dua=extra_dua,
                        selected_range=selected_extra
                    )

                    if disjoint(labels_so_far, extra_obj.all_labels):
                        extra = extra_obj
                        break

                if extra is None:
                    break  # Failed to find a disjoint extra dua

                extra_duas.append(extra)
                # merge_into modifies labels_so_far in place
                merge_into(extra.all_labels, labels_so_far)

        if len(extra_duas) < req_extra:
            continue

        if not trigger_duabytes.dua.fake_dua:
            if not (len(labels_so_far) >= 4 * req_extra):
                continue

        # Calculate max liveness
        c_max_liveness = 0
        for l in trigger_duabytes.all_labels:
            c_max_liveness = max(c_max_liveness, liveness[l])

        # Assertions
        assert bug_type != BugKind.BUG_RET_BUFFER or atp.typ == AtpKind.QUERY_POINT
        assert len(extra_duas) == req_extra

        # --- 7. Save Bug ---
        # The Bug Model expects 'extra_duas' to be a LIST OF IDs (Array[BigInt]),
        # not a list of objects. We extract .id here.
        extra_duas_ids = [d.id for d in extra_duas]

        bug = Bug(
            type=bug_type,
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


def attack_point_lval_usage(ple: dict, session: Session, ind2str: list, project: dict):
    """
    Process an attack point log entry from PANDA logs.
    Args:
        ple (dict): The AttackPoint PANDA Log Entry
        session (Session): The Database connection to input Attack Point data
        ind2str: a list mapping indices to strings from lavadb. This obtains the filename from a number.
    """
    panda_log_entry_attack_point = ple["attackPoint"]
    ast_id = None

    if "astLocId" in panda_log_entry_attack_point["srcInfo"]:
        ast_id = int(panda_log_entry_attack_point["srcInfo"]["astLocId"], 0)
        print(f"attack point id = {ast_id}")

    source_info = panda_log_entry_attack_point["srcInfo"]
    # ignore duas in header files
    if is_header_file(ind2str[source_info["filename"]]):
        return

    print("ATTACK POINT")
    if len(recent_dead_duas) == 0:
        print("no duas yet -- discarding attack point")
        return

    print(f"{len(recent_dead_duas)} viable duas remain")
    assert "astLocId" in source_info
    ast_loc = ASTLoc.from_serialized(ind2str[ast_id])
    assert len(ast_loc.filename) > 0
    attack_point_type = int(panda_log_entry_attack_point["info"], 0)

    atp, is_new_atp = get_or_create(
        session,
        AttackPoint,
        loc=ast_loc,
        typ=attack_point_type
    )

    print(f"@ATP: {str(atp)}")

    # Don't decimate PTR_ADD bugs.
    if attack_point_type == AtpKind.POINTER_WRITE:
        record_injectable_bugs_at(BugKind.BUG_REL_WRITE, atp, is_new_atp, session, [], project)
    if attack_point_type in [AtpKind.POINTER_READ]:
        record_injectable_bugs_at(BugKind.BUG_PTR_ADD, atp, is_new_atp, session, [], project)
    elif attack_point_type == AtpKind.PRINTF_LEAK:
        record_injectable_bugs_at(BugKind.BUG_PRINTF_LEAK, atp, is_new_atp, session, [], project)
    elif attack_point_type == AtpKind.MALLOC_OFF_BY_ONE:
        record_injectable_bugs_at(BugKind.BUG_MALLOC_OFF_BY_ONE, atp, is_new_atp, session, [], project)


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
            if current_run.size > largest_run.size:
                largest_run = current_run
            # Reset
            current_run = Range(0, 0)

    # Final check in case the run goes to the very end of the byte array
    if current_run.size > largest_run.size:
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

def taint_query_pri(ple: dict, session: Session, ind2str: list, inputfile: str, project: dict):
    """
    Process a Taint Query Priority entry to identify potential DUAs (Data Use Associations).
    """
    tqh = ple["taintQueryPri"]

    # 1. Parse Header Info
    # std::min logic: Cap the length at max_lval
    raw_len = int(tqh["len"])
    length = min(raw_len, max_lval)
    num_tainted = int(tqh["numTainted"])

    si = tqh["srcInfo"]
    filename = str(si["filename"])

    # Ignore headers
    if is_header_file(filename):
        return

    instr_addr = int(ple["instr"])
    # print(f"TAINT QUERY HYPERCALL len={length} num_tainted={num_tainted}")

    # 2. Collect Labels & Unique Sets
    all_labels = set()  # Using set for O(1) uniqueness, sorted list later if needed

    # We maintain max stats for this specific DUA
    c_max_tcn = 0
    c_max_card = 0

    # Process new unique label sets from the log
    for tq in tqh["taintQuery"]:
        if "uniqueLabelSet" in tq:
            update_unique_taint_sets(tq["uniqueLabelSet"], session, inputfile)

    # 3. Viability Analysis (Real DUA)
    # Initialize arrays of size 'length'
    viable_byte: list[LabelSet | None] = [None] * length
    byte_tcn = [0] * length

    is_dua = False
    is_fake_dua = False
    num_viable_bytes = 0

    # Optimization: Don't check if we don't have enough tainted bytes
    if num_tainted >= LAVA_MAGIC_VALUE_SIZE:
        for tq in tqh["taintQuery"]:
            offset = int(tq["offset"])
            if offset >= length:
                continue

            ptr = int(tq["ptr"])
            tcn = int(tq["tcn"])

            # Retrieve the LabelSet object from our global map
            ls = ptr_to_labelset.get(ptr)
            if not ls:
                continue  # Safety check

            byte_tcn[offset] = tcn

            # Filtering Logic (Bitwise logic simplified to boolean)
            tcn_too_high = tcn > project["max_tcn"]
            # Note: ls.labels is a list/array
            card_too_high = len(ls.labels) > project["max_card"]

            if (tcn_too_high or card_too_high):
                # print(f"discarding byte {offset}: tcn={tcn_too_high} card={card_too_high}")
                pass
            else:
                # Retain byte
                c_max_tcn = max(tcn, c_max_tcn)
                c_max_card = max(len(ls.labels), c_max_card)

                # Merge labels (Python set update handles deduping)
                all_labels.update(ls.labels)

                viable_byte[offset] = ls
                num_viable_bytes += 1

        # Check DUA Viability
        # 1. Enough viable bytes
        # 2. Enough total labels involved
        # 3. Enough dead bytes (ranges)
        if (num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE and
                len(all_labels) >= LAVA_MAGIC_VALUE_SIZE):

            # get_dead_range expects a list of LabelSets (or None)
            # We assume get_dead_range returns a Range object with a .size property
            dead_range = get_dead_range(viable_byte, [], project)
            if dead_range.size() >= LAVA_MAGIC_VALUE_SIZE:
                is_dua = True

    # 4. Fake DUA Logic (The Fix)
    # If we are making chaff bugs, it's not a real DUA, and we have enough empty space
    if (not is_dua and
            (raw_len - num_tainted) >= LAVA_MAGIC_VALUE_SIZE):

        # Reset viable_byte to clean slate for fake generation
        viable_byte = [None] * length

        # Identify occupied offsets
        occupied_offsets = set()
        for tq in tqh["taintQuery"]:
            occupied_offsets.add(int(tq["offset"]))

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
        # Iterate the BUFFER (not the taint queries) to find gaps
        for i in range(length):
            if i not in occupied_offsets:
                viable_byte[i] = fake_ls
                count += 1
                if count >= LAVA_MAGIC_VALUE_SIZE:
                    break

        # If we successfully found 4 bytes
        if count >= LAVA_MAGIC_VALUE_SIZE:
            is_fake_dua = True

    # 5. Database Persistence & Registration
    assert not (is_dua and is_fake_dua)

    if is_dua or is_fake_dua:
        assert "astLocId" in si
        ast_loc_id = int(si["astLocId"])

        # Create ASTLoc object
        ast_loc = ASTLoc.from_serialized(ind2str[ast_loc_id])
        assert len(ast_loc.filename) > 0

        # Create SourceLval
        lval, _ = get_or_create(
            session,
            SourceLval,
            loc=ast_loc,
            ast_node_name=str(si["astnodename"]),
            len=length
        )

        # Create Dua
        # Note: all_labels is a set, convert to sorted list for DB array
        sorted_labels = sorted(list(all_labels))
        dua, is_new_dua = get_or_create(
            session,
            Dua,
            lval=lval,
            inputfile=inputfile,
            instr=instr_addr,
            fake_dua=is_fake_dua,
            # Defaults for creation:
            defaults={
                "viable_bytes": [ls for ls in viable_byte if ls is not None],  # Relationship needs list of objects
                "byte_tcn": byte_tcn,
                "all_labels": sorted_labels,
                "max_tcn": c_max_tcn,
                "max_cardinality": c_max_card
            }
        )

        # Track Dependencies
        if is_dua:
            for l in sorted_labels:
                dua_dependencies[l] = dua

        # Handle Buffer Overflow Injection (RET_BUFFER)
        # Create AttackPoint (QUERY_POINT)
        pad_atp, is_new_atp = get_or_create(
            session,
            AttackPoint,
            loc=ast_loc,
            typ=AtpKind.QUERY_POINT
        )

        if length >= 20 and decimate_by_type(BugKind.BUG_RET_BUFFER):
            exploit_range = get_dua_exploit_pad(dua)

            # create(DuaBytes...)
            dua_bytes, _ = get_or_create(
                session,
                DuaBytes,
                dua=dua,
                selected_range=exploit_range
            )

            if is_fake_dua or exploit_range.size() >= 20:
                record_injectable_bugs_at(
                    BugKind.BUG_RET_BUFFER,
                    pad_atp,
                    is_new_atp,
                    session,
                    [dua_bytes],
                    project
                )

        # print("OK DUA.")

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

            # print("previously observed lval")
        else:
            # print("new lval")
            pass

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
        # print(f"discarded {num_viable_bytes} viable bytes {len(all_labels)} labels...")
        pass

def get_or_create(session, model, defaults: dict=None, **kwargs):
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


def update_unique_taint_sets(unique_label_set: dict, session: Session, inputfile: str):
    """
    Update the global mapping of unique taint sets based on the provided unique_label_set from PANDA Log.
    Args:
        unique_label_set (dict): the Panda Log unique label set
        session (Session): The SQLAlchemy session for database operations.
        inputfile (str): the input file_name that caused the bug
    """
    pointer = int(unique_label_set["ptr"])

    # The Lookup Logic (Major Fix)
    # C++ was checking if the pointer existed.
    # Python dicts are Hash Maps. Lookups are O(1).
    if pointer not in ptr_to_labelset:
        # Ensure labels are integers (C++ did a conversion)
        labels = [int(x) for x in unique_label_set["label"]]

        # 3. Create LabelSet and append to global map
        label_set = LabelSet(
            id=0,
            ptr=pointer,
            inputfile=inputfile,
            labels=labels
        )
        ptr_to_labelset[pointer] = label_set


def update_liveness(panda_log_entry: dict, session: Session, inputfile: str, project: dict):
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
        session (Session): The SQLAlchemy session for database operations.
        inputfile (str): The name of the file currently being processed (used for tracking LabelSets).

    Side Effects:
        - Modifies global `liveness` (increments counts).
        - Modifies global `recent_dead_duas` and `recent_duas_by_instr` (removes items).
        - Modifies global `dua_dependencies` (removes items).
        - Updates the database (via `update_unique_taint_sets`).
    """
    assert panda_log_entry is not None
    tainted_branch = panda_log_entry["taintedBranch"]
    assert tainted_branch is not None
    print("TAINTED BRANCH\n")

    all_labels = []
    for taint_query in tainted_branch["taintQuery"]:
        assert taint_query
        if taint_query["uniqueLabelSet"]:
            # This will be updating the database with new LabelSets as needed
            update_unique_taint_sets(taint_query["uniqueLabelSet"], session, inputfile)
        pointer = int(taint_query["ptr"])
        cur_labels = ptr_to_labelset[pointer].labels
        merge_into(cur_labels, all_labels)

    duas_to_check = []
    for label in all_labels:
        liveness[label] += 1
        print(f"checking viability of {len(recent_dead_duas)} duas\n")
        depends = dua_dependencies.get(label)
        if depends:
            if isinstance(depends, list):
                merge_into(depends, duas_to_check)
            else:
                merge_into([depends], duas_to_check)

    non_viable_duas = []
    for dua in duas_to_check:
        if not is_dua_dead(dua, project):
            print(f"{str(dua)}\n ** DUA not viable\n")
            recent_dead_duas.pop(dua.lval.id, None)
            if dua in recent_duas_by_instr:
                recent_duas_by_instr.remove(dua)
            assert len(recent_dead_duas) == len(recent_duas_by_instr)
            non_viable_duas.append(dua)

    print(f"{len(non_viable_duas)} non-viable duas \n")
    for dua in non_viable_duas:
        for label in dua.all_labels:
            if label in dua_dependencies:
                dua_dependencies.pop(label, None)


def is_dua_dead(dua: Dua, project: dict) -> bool:
    return get_dua_dead_range(dua, [], project).size() == LAVA_MAGIC_VALUE_SIZE


def get_dua_dead_range(dua: Dua, to_avoid, project: dict):
    viable_bytes = dua.viable_bytes
    print("checking viability of dua: currently %u viable bytes\n", count_nonzero(viable_bytes))
    if "nodua" in dua.lval.ast_name:
        print("Found nodua symbol, skipping")
        print(dua.lval.ast_name)
        print("\n")
        empty = Range(0, 0)
        return empty
    result = get_dead_range(dua.viable_bytes, to_avoid, project)
    print("%s\ndua has %u viable bytes\n", str(dua), result.size())
    return result


# get first 4-or-larger dead range. to_avoid is a sorted vector of labels that
# can't be used
def get_dead_range(viable_bytes: list[LabelSet], to_avoid, project):
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
                    if liveness[label] > project["max_liveness"]:
                        print("byte offset is nonviable b/c label %d has liveness %lu\n", label, liveness[label])
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


def load_idb(file_name: str) -> list:
    x = load_db(file_name)
    return invert_db(x)


def load_db(db_file: str) -> dict[str, int]:
    """
    Loads a database file containing alternating null-terminated integer and string pairs.
    Args:
        db_file (str): Path to the database file to load.
    Returns:
        dict: A dictionary mapping string keys to integer values.
    """
    string_ids = {}
    with open(db_file, 'rb') as db:
        buffer = b''
        fields = []
        while True:
            chunk = db.read(4096)
            if not chunk:
                break
            buffer += chunk
            while b'\0' in buffer:
                part, buffer = buffer.split(b'\0', 1)
                fields.append(part)
                if len(fields) == 2:
                    istr = fields[0].decode('utf-8')
                    str_key = fields[1].decode('utf-8')
                    string_ids[str_key] = int(istr, 0)
                    fields = []
        # Handle any remaining fields (incomplete pair)
        if len(fields) == 2:
            istr = fields[0].decode('utf-8')
            str_key = fields[1].decode('utf-8')
            string_ids[str_key] = int(istr, 0)
    return string_ids


def invert_db(n2ind: dict) -> list[str]:
    """
    Inverts a dict mapping strings to integers into a list where the index is the integer
    and the value is the string.

    Args:
        n2ind (dict): Dictionary mapping strings to integers.

    Returns:
        list: List of strings, where each index corresponds to the integer value.
    """
    if not n2ind:
        return []
    max_index = max(n2ind.values())
    ind2n = [None] * (max_index + 1)
    for k, v in n2ind.items():
        ind2n[v] = k
    return ind2n


def parse_panda_log(panda_log_file: str, project_data: dict, program_name: str):
    """
    Main function for Find Bug Inject (FBI) tool.
    """
    # maps from ind -> (filename, lvalname, attackpointname)
    root_directory = project_data["output_dir"]
    directory = f"{root_directory}/{program_name}"
    lavadb = f"{directory}/lavadb"
    lava_db = load_idb(lavadb)
    print(f"{len(lava_db)} strings in lavadb")

    pgpass = os.getenv("POSTGRES_USER")
    pguser = os.getenv("POSTGRES_PASSWORD")
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
                    taint_query_pri(ple, db.session, lava_db, inputfile, project_data)
                elif "taintedBranch" in ple:
                    update_liveness(ple, db.session, inputfile, project_data)
                elif "attackPoint" in ple:
                    attack_point_lval_usage(ple, db.session, lava_db, project_data)
                elif "dwarfCall" in ple:
                    record_call(ple)
                elif "dwarfRet" in ple:
                    record_ret(ple)

                if 0 < curtail < num_real_duas:
                    print(f"*** Curtailing output of fbi at {num_real_duas}")
                    break

    print(f"{num_bugs_added_to_db} added to db")
    print(f"{num_potential_bugs} potential bugs")
    print(f"{num_potential_nonbugs} potential non bugs")

    if num_potential_bugs == 0:
        print("No bugs found", file=sys.stderr)
        raise RuntimeError("No bugs found by FBI")


if __name__ == "__main__":
    curtail = int(sys.argv[5]) if len(sys.argv) == 6 else 0
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

    if curtail == 0:  # Will be 0 unless specified on command line
        if not isinstance(project.get("curtail_fbi", 0), int):
            project["curtail"] = 0
    print(f"Curtail is {project['curtail']}")

    inputfile = sys.argv[4]

    parse_panda_log(panda_log, project, project_name)
