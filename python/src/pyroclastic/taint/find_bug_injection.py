import json
import sys
import ijson
import os
from sqlalchemy.exc import IntegrityError
from typing import Iterable, TypeVar, DefaultDict, Set, Optional, cast
from collections import defaultdict
from sqlalchemy.orm import Session

from ..utils.database_types import AttackPoint, \
    ASTLoc, DuaBytes, SourceLval, LabelSet, Dua, Range, LavaDatabase, AtpKind
from ..utils.vars import parse_vars

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


def attack_point_lval_usage(ple: dict, session: Session, ind2str: dict[int, str], project_data: dict):
    """
    Process an attack point log entry from PANDA logs.
    Args:
        ple (dict): The AttackPoint PANDA Log Entry
        session (Session): The Database connection to input Attack Point data
        ind2str: a list mapping indices to strings from lavadb. This obtains the filename from a number.
        project_data: a dict of input values
    """
    attack_point = ple["attackPoint"]
    source_info = attack_point["srcInfo"]
    ast_id = source_info["astLocId"]
    dprint(project_data, f"attack point id = {ast_id}")

    # ignore duas in header files
    # Remember, in PandaLog, AttackPoint filenames are numbers!
    if is_header_file(ind2str[ast_id]):
        return

    dprint(project_data, "ATTACK POINT")
    if len(recent_dead_duas) == 0:
        dprint(project_data, "no duas yet -- discarding attack point")
        return

    dprint(project_data, f"{len(recent_dead_duas)} viable duas remain")
    ast_loc: ASTLoc = ASTLoc.from_serialized(ind2str[ast_id])
    attack_point_type = attack_point["info"]

    atp = get_or_create(
        session,
        AttackPoint,
        loc=ast_loc,
        type=attack_point_type
    )
    dprint(project_data, f"@ATP: {str(atp)}")


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
    length: int = min(taint_query_header["len"], project_data["max_lval_size"])
    num_tainted: int = taint_query_header["numTainted"]

    source_info = taint_query_header["srcInfo"]
    filename = source_info["filename"]

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
            update_unique_taint_sets(taint_query["uniqueLabelSet"], session, project_data)

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
            offset: int = taint_query["offset"]
            if offset >= length:
                continue
            dprint(project_data,f"considering offset = {offset}")
            ptr = int(taint_query["ptr"], 0)
            tcn = taint_query["tcn"]

            # Retrieve the LabelSet object from our global map
            label_set = ptr_to_labelset.get(ptr)
            if not label_set:
                continue

            byte_tcn[offset] = tcn

            # Filtering Logic (Bitwise logic simplified to boolean)
            tcn_too_high = tcn > project_data["max_tcn"]
            # Note: ls.labels is a list/array
            card_too_high = len(label_set.labels) > project_data["max_cardinality"]

            current_byte_not_ok = tcn_too_high or card_too_high

            # REPLICATING LAVA C++ BUG:
            # Bytes are ONLY discarded if debug mode is ON!
            # "if (current_byte_not_ok && debug)"
            debug = project_data.get("debug", False)
            if current_byte_not_ok and debug:
                dprint(project_data, f"discarding byte {offset}...")
            else:
                dprint(project_data, "retaining byte")
                # THIS IS THE C++ UNCONDITIONAL RETAIN LOGIC!
                c_max_tcn = max(tcn, c_max_tcn)
                c_max_card = max(len(label_set.labels), c_max_card)

                viable_byte[offset] = label_set
                num_viable_bytes += 1

            # Merge labels (Python set update handles deduping)
            all_labels.update(label_set.labels)
            dprint(project_data, f"keeping byte @ offset {offset}")
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
    cpp_style_diff = (length - num_tainted)
    if (project_data.get('chaff_bugs', False) and not is_dua and
            cpp_style_diff >= LAVA_MAGIC_VALUE_SIZE):

        dprint(project_data, "not enough taint -- what about non-taint?")
        dprint(project_data, f"len={length} num_tainted={num_tainted}")

        # Reset viable_byte to clean slate for fake generation
        viable_byte = [None] * length

        # Get the Singleton Fake LabelSet (Get or Create)
        # 0xFA4E is a magic number often used for fake flags
        fake_ls = get_or_create(
            session,
            LabelSet,
            ptr=FAKE_DUA_BYTE_FLAG,
            inputfile="fakedua",
            default={"labels" : []}
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
        ast_loc_id = source_info["astLocId"]

        # Create ASTLoc object
        ast_loc: ASTLoc = ASTLoc.from_serialized(ind2str[ast_loc_id])

        # Create SourceLval
        lval: SourceLval = cast(SourceLval, get_or_create(
            session,
            SourceLval,
            loc=ast_loc,
            ast_name=str(source_info["astnodename"]),
            defaults={'len_bytes': length}
        ))

        # Create Dua
        # Note: all_labels is a set, convert to sorted list for DB array
        sorted_labels = sorted(list(all_labels))
        dua: Dua = cast(Dua, get_or_create(
            session,
            Dua,
            lval=lval.id,
            inputfile=project_data.get("input", "unknown"),
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
        ))

        # Track Dependencies
        if is_dua:
            for l in sorted_labels:
                dua_dependencies[l].add(dua)

        # Handle Buffer Overflow Injection (RET_BUFFER)
        # Create AttackPoint (QUERY_POINT)
        get_or_create(
            session,
            AttackPoint,
            loc=ast_loc,
            type=AtpKind.QUERY_POINT
        )

        if length >= 20:
            exploit_range = get_dua_exploit_pad(dua)

            # create(DuaBytes...)
            get_or_create(
                session,
                DuaBytes,
                dua=dua.id,
                selected=exploit_range
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


def get_or_create(session: Session, model, defaults: Optional[dict] = None, **kwargs):
    """
    Retrieves object or creates it using an EXISTING session.
    Args:
        session: The SQLAlchemy session to use.
        model: The SQLAlchemy model class.
        defaults: A dict of default values to use when creating the object.
        **kwargs: The lookup parameters.
    """
    if 'default' in kwargs:
        defaults = kwargs.pop('default')

    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        params = {**kwargs, **(defaults or {})}
        instance = model(**params)
        session.add(instance)
        try:
            session.flush()
            return instance
        except IntegrityError:
            session.rollback()
            instance = session.query(model).filter_by(**kwargs).first()
            if instance:
                return instance
            else:
                raise


def update_unique_taint_sets(unique_label_set: dict, session: Session, project_data: dict):
    """
    Update the global mapping of unique taint sets based on the provided unique_label_set from PANDA Log.
    Args:
        unique_label_set (dict): the Panda Log unique label set
        session (Session): Database session too add the LabelSet
        project_data (dict): Lava project parameters
    """
    dprint(project_data, "UNIQUE TAINT SET")
    dprint(project_data, json.dumps(unique_label_set))
    ptr_str = str(unique_label_set["ptr"])
    pointer = int(ptr_str, 0)

    # The Lookup Logic (Major Fix)
    # C++ was checking if the pointer existed.
    # Python dicts are Hash Maps. Lookups are O(1).
    if pointer not in ptr_to_labelset:
        # Ensure labels are integers (C++ did a conversion)
        labels = [int(str(x), 0) for x in unique_label_set["label"]]

        # 3. Create LabelSet and append to global map
        label_set = cast(LabelSet, get_or_create(
            session,
            LabelSet,
            ptr=pointer,
            defaults={
                "inputfile": project_data.get("input", "unknown"),
                "labels": labels
            }
        ))
        ptr_to_labelset[pointer] = label_set
    dprint(project_data, f"{len(ptr_to_labelset)} unique taint sets\n")


def update_liveness(panda_log_entry: dict, session: Session, project_data: dict):
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
    tainted_branch = panda_log_entry["taintedBranch"]
    dprint(project_data, "TAINTED BRANCH")

    all_labels = []
    for taint_query in tainted_branch["taintQuery"]:
        if "uniqueLabelSet" in taint_query:
            # This will be updating the database with new LabelSets as needed
            update_unique_taint_sets(taint_query["uniqueLabelSet"], session, project_data)
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
            recent_dead_duas.pop(dua.lval_relationship.id, None)
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
    if "nodua" in dua.lval_relationship.ast_name:
        dprint(project_data, f"Found nodua symbol, skipping {dua.lval_relationship.ast_name}")
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
    """
    Load the LavaDB file and create a map for adding bugs into the Lava Database
    Args:
        db_file: input Lava database file mapping IDs to strings (e.g., "3" -> "toy.c:...")
    """
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
                    update_liveness(ple, db.session, project_data)
                elif "attackPoint" in ple:
                    attack_point_lval_usage(ple, db.session, lava_db, project_data)
                elif "dwarfCall" in ple:
                    record_call(ple)
                elif "dwarfRet" in ple:
                    record_ret(ple)
                elif "fileTaintMatch" in ple:
                    project_data['input'] = os.path.basename(ple['fileTaintMatch']['filename'])

                if 0 < project_data.get("curtail", 0) < num_real_duas:
                    print(f"*** Curtailing output of fbi at {num_real_duas}")
                    break

            # Once you are done, and no error on the entire log, update the database
            db.session.commit()


def print_bug_stats(project_data: dict):
    """
    Examines and prints the complete structural contents of all mined elements
    in a deterministic order, safely handling any nested database sequences.
    """

    def dump_table(title, rows, attributes):
        print(f"\n==================================================")
        print(f"=== {title} (Row Count: {len(rows)}) ===")
        print(f"==================================================")
        for idx, row in enumerate(rows):
            print(f"  [{idx}] Row Instance Entry:")
            for attr in attributes:
                if hasattr(row, attr):
                    val = getattr(row, attr)

                    # Track list inner types cleanly for your surgical debugging verification
                    if isinstance(val, list):
                        inner_type = f"list of {type(val[0]).__name__}" if val else "empty list"
                        # Limit output size to prevent terminal buffer spam on giant label lists
                        display_val = val if len(val) <= 12 else f"{val[:10]}... (+{len(val) - 10} more)"
                        # FIX: Coerce the array token to a string BEFORE passing alignment modifiers
                        str_val = str(display_val)
                    else:
                        inner_type = type(val).__name__
                        str_val = str(val)

                    print(f"    - {attr:<16}: {str_val:<55} | Type: {inner_type}")
                else:
                    print(f"    - {attr:<16}: [NOT FOUND ON OBJECT VALUE]")

    with LavaDatabase(project_data) as db:
        session = db.session

        # 1. SourceLvals (Deterministic sort by primary key id)
        try:
            source_lvals = session.query(SourceLval).order_by(SourceLval.id).all()
        except Exception:
            source_lvals = session.query(SourceLval).all()
        dump_table("SOURCE LVALS", source_lvals, ['id', 'ast_name', 'len_bytes', 'loc'])

        # 2. LabelSets (Deterministic sort by PANDA memory pointer address)
        try:
            label_sets = session.query(LabelSet).order_by(LabelSet.ptr).all()
        except Exception:
            label_sets = session.query(LabelSet).all()
        dump_table("LABEL SETS", label_sets, ['id', 'ptr', 'inputfile', 'labels'])

        # 3. AttackPoints (Deterministic sort by database primary key id)
        try:
            attack_points = session.query(AttackPoint).order_by(AttackPoint.id).all()
        except Exception:
            attack_points = session.query(AttackPoint).all()
        dump_table("ATTACK POINTS", attack_points, ['id', 'type', 'loc'])

        # 4. DUAs (Deterministic sort by absolute trace execution instruction address)
        try:
            duas = session.query(Dua).order_by(Dua.instr, Dua.id).all()
        except Exception:
            duas = session.query(Dua).all()
        dump_table("DUAs (Def-Use Associations)", duas, [
            'id', 'lval', 'instr', 'fake_dua', 'inputfile',
            'max_tcn', 'max_cardinality', 'all_labels', 'byte_tcn', 'viable_bytes'
        ])

        # 5. DuaBytes (Deterministic sort by parent DUA reference ID)
        try:
            dua_bytes = session.query(DuaBytes).order_by(DuaBytes.dua).all()
        except Exception:
            dua_bytes = session.query(DuaBytes).all()
        dump_table("DUA BYTES (Exploit Ranges)", dua_bytes, ['id', 'dua', 'selected'])


def main():
    project_name = sys.argv[1]
    panda_log = sys.argv[2]

    # host_json reads overall config from host.json, project_name finds configs for specific project
    project = parse_vars(project_name)

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
        print("curtail not set, using default 0")
        project["curtail"] = 0
    if not isinstance(project["curtail"], int):
        raise RuntimeError("Could not parse curtail")

    parse_panda_log(panda_log, project)


if __name__ == "__main__":
    main()
