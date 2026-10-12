import sys
import ijson
import os
import re
from sqlalchemy import event, select
from sqlalchemy.exc import IntegrityError
from typing import DefaultDict, Set, Optional, List, Tuple, cast
from collections import defaultdict
from sqlalchemy.orm import Session, joinedload
from ..utils.database_types import print_bug_stats
from ..utils.database_types import SourceTrace, CallTrace
from ..utils.database_types import AttackPoint, ASTLoc, SourceLval, LabelSet, LavaDatabase, Dua
from ..utils.database_types import AtpKind, AtpExecution, LivenessDelta
from ..taint.taint_utils import get_dua_dead_range, get_dead_range, merge_into
from ..utils.vars import parse_vars

# Matches "libc" at clean boundaries:
# - Preceded by: start of string (^), a slash (/), or a bang (!)
# - Followed by: a dot (.), a hyphen (-), a bang (!), or end of string ($)
# This ignores things like "my_libc_func" or "alibc.c"
LIBC_BOUNDARY_RE = re.compile(r'(?:^|/|!)libc(?:[-.!]|$)', re.IGNORECASE)

# These map pointer values in the PANDA taint run to the sets they refer to.
ptr_to_labelset: dict[int, LabelSet] = {}

# Map from label to duas that are tainted by that label.
# So when we update liveness, we know what duas might be invalidated.
dua_dependencies: DefaultDict[int, Set[Dua]] = defaultdict(set)

# Liveness for each input byte.
# liveness: DefaultDict[int, int] = defaultdict(int)
liveness_by_file = defaultdict(lambda: defaultdict(int))

# number of bytes in lava magic value used to trigger bugs
LAVA_MAGIC_VALUE_SIZE: int = 4
# special flag to indicate untainted byte that we want to use for fake dua
FAKE_DUA_BYTE_FLAG: int = 777

# Active DUAs in discovery order, with constant-time membership/removal.
# set(recent_dead_duas.values()) == set(recent_duas_by_instr).
recent_duas_by_instr: dict[Dua, None] = {}
# Map from source lval ID to most recent DUA incarnation.
recent_dead_duas: dict[int, Dua] = {}

num_real_duas : int = 0
num_fake_duas : int = 0

current_call_stack: List[Tuple[str, str]] = []

# A generalized, global in-memory cache for all database models
_L1_CACHE = {}

# A global to prevent duplicate liveness snapshots for the same instruction
last_snapshotted_instr: int = -1

# Bound temporary row buffers; batches remain inside the whole-log transaction.
MINING_INSERT_BATCH_SIZE = 1000


def record_atp_execution(session: Session, *, atp_id: int, inputfile: str,
                         instr: int, pid: int = 0, tid: int = 0):
    """Buffer executions in first-observation order in the single-writer miner.

    IDs are only consumed by Phase II, after the mining transaction commits.
    Existing identities are loaded once per input file; their first payload wins.
    """
    if not session.info.get("mining_atp_execution_hooks"):
        event.listen(session, "before_commit", flush_atp_executions)
        event.listen(session, "after_soft_rollback", _rollback_atp_executions)
        session.info["mining_atp_execution_hooks"] = True
    state = session.info.setdefault("mining_atp_executions", {"keys": {}, "rows": []})
    keys_by_file = state["keys"]
    if inputfile not in keys_by_file:
        table = AtpExecution.__table__
        rows = session.connection().execute(
            select(table.c.atp, table.c.instr).where(table.c.inputfile == inputfile))
        keys_by_file[inputfile] = {(row.atp, row.instr) for row in rows}
    key = (atp_id, instr)
    if key in keys_by_file[inputfile]:
        return
    keys_by_file[inputfile].add(key)
    state["rows"].append(dict(atp=atp_id, inputfile=inputfile, instr=instr, pid=pid, tid=tid))
    if len(state["rows"]) >= MINING_INSERT_BATCH_SIZE:
        flush_atp_executions(session)


def flush_atp_executions(session: Session):
    state = session.info.get("mining_atp_executions")
    if state and state["rows"]:
        session.connection().execute(AtpExecution.__table__.insert(), state["rows"])
        state["rows"].clear()


def _rollback_atp_executions(session: Session, previous_transaction):
    # Root rollback invalidates both buffered and inserted identities. A generic
    # get-or-create SAVEPOINT rollback must not discard unrelated executions.
    if previous_transaction.parent is None:
        session.info.pop("mining_atp_executions", None)


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
    current_instr = int(ple["instr"], 0)

    # ignore duas in header files
    # Remember, in PandaLog, AttackPoint filenames are numbers!
    if is_header_file(ind2str[ast_id]):
        return

    if len(recent_dead_duas) == 0:
        return

    ast_loc: ASTLoc = ASTLoc.from_serialized(ind2str[ast_id])
    attack_point_type = attack_point["info"]

    atp = cast(AttackPoint, get_or_create(
        session,
        AttackPoint,
        loc=ast_loc,
        type=attack_point_type,
    ))
    record_atp_execution(
        session,
        atp_id=atp.id,
        inputfile=project_data.get("input_file", "UNKNOWN_FILE"),
        instr=current_instr,
        pid=project_data.get("pid", 0),
        tid=project_data.get("tid", 0)
    )
    save_liveness_to_db(session, current_instr)


# Assuming globals/constants are available:
# max_lval, LAVA_MAGIC_VALUE_SIZE, max_tcn, max_card, ptr_to_labelset
# dua_dependencies, recent_dead_duas, recent_duas_by_instr
# num_real_duas, num_fake_duas, chaff_bugs, FAKE_DUA_BYTE_FLAG

def taint_query_pri(ple: dict, session: Session, ind2str: dict[int, str], project_data: dict,
                    source_trace_index: int, random_sampling_threshold = 2):
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
    stack_offset: int = source_info["insertionpoint"]

    # Ignore headers
    if is_header_file(filename):
        return

    instr_addr = int(ple["instr"], 0)

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
    viable_byte: List[LabelSet | None] = [None] * length
    byte_tcn = [0] * length

    is_dua = False
    is_fake_dua = False
    num_viable_bytes = 0

    # Optimization: Don't check if we don't have enough tainted bytes
    if num_tainted >= LAVA_MAGIC_VALUE_SIZE:
        for taint_query in taint_query_header["taintQuery"]:
            offset: int = taint_query["offset"]
            if offset >= length:
                continue
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
            if not (current_byte_not_ok and debug):
                # THIS IS THE C++ UNCONDITIONAL RETAIN LOGIC!
                c_max_tcn = max(tcn, c_max_tcn)
                c_max_card = max(len(label_set.labels), c_max_card)

                viable_byte[offset] = label_set
                num_viable_bytes += 1

            # Merge labels (Python set update handles deduping)
            all_labels.update(label_set.labels)

        # Check DUA Viability
        # 1. Enough viable bytes
        # 2. Enough total labels involved
        # 3. Enough dead bytes (ranges)
        if (num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE and
                len(all_labels) >= LAVA_MAGIC_VALUE_SIZE):

            # get_dead_range expects a list of LabelSets (or None)
            # We assume get_dead_range returns a Range object with a .size property
            liveness = liveness_by_file[project_data.get("input_file", "UNKNOWN_FILE")]
            dead_range = get_dead_range(viable_byte, [], liveness, project_data)
            if dead_range.size() >= LAVA_MAGIC_VALUE_SIZE:
                is_dua = True

    # 4. Fake DUA Logic (The Fix)
    # If we are making chaff bugs, it's not a real DUA, and we have enough empty space
    cpp_style_diff = (length - num_tainted)
    if (project_data.get('chaff_bugs', False) and not is_dua and
            cpp_style_diff >= LAVA_MAGIC_VALUE_SIZE):


        # Reset viable_byte to clean slate for fake generation
        viable_byte: List[LabelSet | None] = [None] * length

        # Get the Singleton Fake LabelSet (Get or Create)
        # 0xFA4E is a magic number often used for fake flags
        fake_ls: LabelSet = cast(LabelSet, get_or_create(
            session,
            LabelSet,
            ptr=FAKE_DUA_BYTE_FLAG,
            inputfile="fakedua",
            default={"labels" : []}
        ))

        count = 0
        # 'i' starts at 0 and increments every time we look at a taint query
        # This matches the C++ loop where ++i happens at the bottom of every iteration
        for i, taint_query in enumerate(taint_query_header["taintQuery"]):
            offset: int = taint_query["offset"]

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
    assert not (is_dua and is_fake_dua)

    ast_loc_id: int = source_info["astLocId"]

    # Create ASTLoc object
    ast_loc: ASTLoc = ASTLoc.from_serialized(ind2str[ast_loc_id])

    calltrace_ids : list[int] = []
    for file_callee, function_callee in current_call_stack:
        ct = cast(CallTrace, get_or_create(
            session,
            CallTrace,
            caller=function_callee,
            file=file_callee,
        ))
        calltrace_ids.append(ct.id)

    # Create AttackPoint (QUERY_POINT) for Chaff Bugs
    atp = cast(AttackPoint, get_or_create(
        session,
        AttackPoint,
        loc=ast_loc,
        type=AtpKind.QUERY_POINT,
        defaults={
            'trace_index' : source_trace_index,    
            'stack_offset' : stack_offset,
            'calltrace' : calltrace_ids,
        }
    ))

    record_atp_execution(
        session,
        atp_id=atp.id,
        inputfile=project_data.get("input_file", "UNKNOWN_FILE"),
        instr=instr_addr,
        pid=project_data.get("pid", 0),
        tid=project_data.get("tid", 0)
    )
    save_liveness_to_db(session, instr_addr)

    if is_dua or is_fake_dua:
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
            inputfile=project_data.get("input_file", "UNKNOWN_FILE"),
            instr=instr_addr,
            fake_dua=is_fake_dua,

            # --- DATA PAYLOAD (Only used if creating a NEW entry) ---
            defaults={
                'viable_bytes': viable_byte,
                'byte_tcn': byte_tcn,
                'all_labels': sorted_labels,
                'max_tcn': c_max_tcn,
                'max_cardinality': c_max_card,
                'trace_index': source_trace_index,
            }
        ))

        # Track Dependencies
        if is_dua:
            for l in sorted_labels:
                dua_dependencies[l].add(dua)

        # 6. Global State Maintenance (recent_dead_duas)
        # Logic: Replace old DUA with same lval_id, or insert new.

        lval_id = lval.id

        if lval_id in recent_dead_duas:
            # We have seen this LVAL before. Replace it.
            old_dua = recent_dead_duas[lval_id]

            if old_dua in recent_duas_by_instr:
                del recent_duas_by_instr[old_dua]
                old_dua.death_instr = instr_addr

            # Clean up old dependencies
            for l in old_dua.all_labels:
                if old_dua in dua_dependencies[l]:
                    dua_dependencies[l].remove(old_dua)

        # Insert/Update the map
        recent_dead_duas[lval_id] = dua

        # Enforce sorted order logic for recent_duas_by_instr
        # C++ did: assert(dua->instr >= recent_duas_by_instr.back()->instr);
        # This implies the log is processed in execution order, so we can just append.
        recent_duas_by_instr[dua] = None

        # Verify invariants
        assert len(recent_dead_duas) == len(recent_duas_by_instr), "Mismatched counts between recent_dead_duas and recent_duas_by_instr"

        # 7. Update Stats (Global)
        global num_real_duas, num_fake_duas
        if is_dua:
            num_real_duas += 1
        if is_fake_dua:
            num_fake_duas += 1


def _make_hashable(val):
    """Safely converts arbitrary kwargs (like ASTLoc or lists) into hashable tuple keys."""
    if isinstance(val, (int, str, float, bool, tuple, type(None))):
        return val
    if isinstance(val, list):
        return tuple(_make_hashable(x) for x in val)
    if hasattr(val, '__hash__') and val.__hash__ is not None:
        try:
            hash(val)
            return val
        except TypeError:
            pass
    return str(val)


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

    # 1. Build a unique cache key based on the model and the search parameters
    hashable_kwargs = tuple(sorted((k, _make_hashable(v)) for k, v in kwargs.items()))
    cache_key = (model, hashable_kwargs)

    # 2. Check the memory cache BEFORE touching the database/session
    if cache_key in _L1_CACHE:
        return _L1_CACHE[cache_key]

    # 3. Standard DB lookup
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        _L1_CACHE[cache_key] = instance
        return instance
    else:
        params = {**kwargs, **(defaults or {})}
        instance = model(**params)
        if session.info.get("atomic_mining", False):
            # The single-writer import owns one outer transaction. Any insert
            # failure aborts the whole log, so per-entity SAVEPOINTs buy nothing.
            session.add(instance)
            session.flush()
            _L1_CACHE[cache_key] = instance
            return instance
        session.add(instance)
        try:
            with session.begin_nested():
                session.flush()
            _L1_CACHE[cache_key] = instance
            return instance
        except IntegrityError:
            instance = session.query(model).filter_by(**kwargs).first()
            if instance:
                _L1_CACHE[cache_key] = instance
                return instance
            else:
                raise


def update_unique_taint_sets(unique_label_set: dict, session: Session, project_data: dict):
    """
    Update the global mapping of unique taint sets based on the provided unique_label_set from PANDA Log.
    Args:
        unique_label_set (dict): the Panda Log unique label set
        session (Session): Database session to add the LabelSet
        project_data (dict): Lava project parameters
    """
    ptr_str = str(unique_label_set["ptr"])
    pointer = int(ptr_str, 0)

    # The Lookup Logic (Major Fix)
    # C++ was checking if the pointer existed.
    # Python dicts are Hash Maps. Lookups are O(1).
    if pointer not in ptr_to_labelset:
        # Ensure labels are integers (C++ did a conversion)
        labels = sorted([int(str(x), 0) for x in unique_label_set["label"]])

        # 3. Create LabelSet and append to global map
        label_set = cast(LabelSet, get_or_create(
            session,
            LabelSet,
            ptr=pointer,
            defaults={
                "inputfile": project_data.get("input_file", "UNKNOWN_FILE"),
                "labels": labels
            }
        ))
        ptr_to_labelset[pointer] = label_set


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
        session (Session): Database session to store on Database
        project_data (dict): Configuration data for viability checks.

    Side Effects:
        - Modifies global `liveness` (increments counts).
        - Modifies global `recent_dead_duas` and `recent_duas_by_instr` (removes items).
        - Modifies global `dua_dependencies` (removes items).
    """
    current_file = project_data.get("input_file", "UNKNOWN_FILE")
    liveness = liveness_by_file[current_file]
    current_instr = int(panda_log_entry["instr"], 0)
    tainted_branch = panda_log_entry["taintedBranch"]

    all_labels: set[int] = set()
    for taint_query in tainted_branch["taintQuery"]:
        if "uniqueLabelSet" in taint_query:
            # This will be updating the database with new LabelSets as needed
            update_unique_taint_sets(taint_query["uniqueLabelSet"], session, project_data)
        pointer: int = int(taint_query["ptr"])
        cur_labels: list[int] = ptr_to_labelset[pointer].labels
        merge_into(all_labels, set(cur_labels))

    duas_to_check: set[Dua] = set()
    for label in all_labels:
        liveness[label] += 1
        depends = dua_dependencies.get(label)
        if depends:
            merge_into(duas_to_check, depends)

    non_viable_duas = []
    for dua in duas_to_check:
        if not is_dua_dead(dua, liveness, project_data):
            dua.death_instr = current_instr
            recent_dead_duas.pop(dua.lval_relationship.id, None)
            recent_duas_by_instr.pop(dua, None)
            assert len(recent_dead_duas) == len(recent_duas_by_instr)
            non_viable_duas.append(dua)

    for dua in non_viable_duas:
        for label in dua.all_labels:
            if label in dua_dependencies:
                dua_dependencies.pop(label, None)
    save_liveness_to_db(session, current_instr)


def is_dua_dead(dua: Dua, liveness, project_data: dict) -> bool:
    return get_dua_dead_range(dua, [], liveness, project_data).size() == LAVA_MAGIC_VALUE_SIZE


def record_call(ple: dict):
    """
    Record a Dwarf2 call from Panda Log
    Args:
        :param ple: Pandalog entry
    """
    call = ple["dwarf2Call"]
    file_callee = call["fileCallee"]
    function_callee = call["functionNameCallee"]

    # 1. Instantly catch explicit Linux system library paths
    if file_callee.startswith(("/lib/", "/usr/lib/", "/lib64/")):
        return

    # 2. Use boundary-safe regex to catch PANDA's dynamic formats 
    # (e.g., "libc-2.13.so!malloc" or "libc.so!printf")
    if LIBC_BOUNDARY_RE.search(file_callee) or LIBC_BOUNDARY_RE.search(function_callee):
        return

    current_call_stack.append((file_callee, function_callee))


def record_ret(ple: dict):
    """
    Record a Dwarf2 call from Panda Log
    Args:
        :param ple: Panda Log Entry
    """
    ret = ple["dwarf2Ret"]
    file_callee = ret["fileCallee"]
    function_callee = ret["functionNameCallee"]

    # 1. Instantly catch explicit Linux system library paths
    if file_callee.startswith(("/lib/", "/usr/lib/", "/lib64/")):
        return

    # 2. Use boundary-safe regex to catch PANDA's dynamic formats 
    # (e.g., "libc-2.13.so!malloc" or "libc.so!printf")
    if LIBC_BOUNDARY_RE.search(file_callee) or LIBC_BOUNDARY_RE.search(function_callee):
        return

    if len(current_call_stack) == 0:
        return

    file_callee_on_stack, function_callee_on_stack = current_call_stack[-1]
    assert file_callee_on_stack == file_callee, f"File mismatch: {file_callee_on_stack} != {file_callee}"
    assert function_callee_on_stack == function_callee, f"Function mismatch: {function_callee_on_stack} != {function_callee}"
    current_call_stack.pop()


def record_trace(ple: dict, lava_db: dict[int, str], session: Session, source_trace_index: int):
    source_trace_id : int = ple["sourceTraceId"]["astLocId"]
    ast_loc_string : str = lava_db[source_trace_id]
    ast_loc : ASTLoc = ASTLoc.from_serialized(ast_loc_string)
    get_or_create(
        session,
        SourceTrace,
        loc=ast_loc,
        index=source_trace_index
    )


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
    string_ids: dict[int, str] = {}

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


def save_liveness_to_db(session: Session, atp_instr: int):
    global last_snapshotted_instr

    # Preserve first-snapshot behavior for equal-instruction events.
    if atp_instr == last_snapshotted_instr:
        return

    rows = []
    statement = LivenessDelta.__table__.insert()
    previous_by_file = session.info.setdefault("mining_liveness_counts", {})
    # Core writes use the session's transaction without autoflushing unrelated ORM
    # state. Snapshots have no foreign keys and no consumer needs their ORM objects.
    connection = None
    for input_file, liveness in liveness_by_file.items():
        previous = previous_by_file.setdefault(input_file, {})
        for label, current_count in liveness.items():
            if label in previous and previous[label] == current_count:
                continue
            rows.append(dict(inputfile=input_file, label=label,
                             atp_instr=atp_instr, liveness_count=current_count))
            if len(rows) == MINING_INSERT_BATCH_SIZE:
                if connection is None:
                    connection = session.connection()
                connection.execute(statement, rows)
                rows = []
    if rows:
        if connection is None:
            connection = session.connection()
        connection.execute(statement, rows)

    # Publish the comparison state only after every insert succeeds.
    for input_file, liveness in liveness_by_file.items():
        previous_by_file[input_file] = dict(liveness)
    last_snapshotted_instr = atp_instr


def parse_panda_log(panda_log_file: str, project_data: dict):
    """
    Main function for Find Bug Inject (FBI) tool.
    """
    global last_snapshotted_instr
    last_snapshotted_instr = -1
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

        current_source_trace_id = 0
        # One transaction for the whole import; exceptions roll back all rows.
        with LavaDatabase(project_data) as db, db.session.begin():
            db.session.info["atomic_mining"] = True
            for ple in parser:
                num_entries_read += 1

                if "taintQueryPri" in ple:
                    taint_query_pri(ple, db.session, lava_db, project_data, current_source_trace_id)
                elif "taintedBranch" in ple:
                    update_liveness(ple, db.session, project_data)
                elif "attackPoint" in ple:
                    attack_point_lval_usage(ple, db.session, lava_db, project_data)
                elif "dwarf2Call" in ple:
                    record_call(ple)
                elif "dwarf2Ret" in ple:
                    record_ret(ple)
                elif "sourceTraceId" in ple:
                    record_trace(ple, lava_db, db.session, current_source_trace_id)
                    current_source_trace_id += 1
                elif "fileTaintMatch" in ple:
                    project_data["input_file"] = os.path.basename(ple['fileTaintMatch']['filename'])
                    project_data["pid"] = ple['fileTaintMatch'].get('pid', 0)
                    project_data["tid"] = ple['fileTaintMatch'].get('tid', 0)
                    last_snapshotted_instr = -1
                    db.session.info.pop("mining_liveness_counts", None)
                    # Nuke the global state
                    current_source_trace_id = 0
                    liveness_by_file.clear()
                    dua_dependencies.clear()
                    recent_dead_duas.clear()
                    recent_duas_by_instr.clear()
                    ptr_to_labelset.clear()
                    current_call_stack.clear()
                    _L1_CACHE.clear()

                # Console printing
                if num_entries_read % 10000 == 0:
                    print(f"processed {num_entries_read} pandalog entries")
                    print(f"{len(recent_dead_duas)} current duas {num_real_duas} real duas {num_fake_duas} fake duas")

                if 0 < project_data.get("curtail", 0) < num_real_duas:
                    print(f"*** Curtailing output of fbi at {num_real_duas}")
                    break

            # The transaction context commits only after successful processing.
            # Drain the final partial execution batch before that commit.
            flush_atp_executions(db.session)


def main():
    project_name = sys.argv[1]
    panda_log = sys.argv[2]

    project = parse_vars(project_name)
    parse_panda_log(panda_log, project)


if __name__ == "__main__":
    main()
