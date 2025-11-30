import sys
import json
import os
import random

from scripts.database_types import AttackPoint, Bug, \
    ASTLoc, DuaBytes, SourceLval, LabelSet, Dua, Range, LavaDatabase, BugParam
from scripts.vars import parse_vars
from sqlalchemy.exc import IntegrityError
from typing import Iterable, TypeVar, DefaultDict
from collections import defaultdict

T = TypeVar("T")

# Map from source lval ID to most recent DUA incarnation.
recent_dead_duas: dict[int, Dua] = {}

# These map pointer values in the PANDA taint run to the sets they refer to.
ptr_to_labelset: dict[int, LabelSet] = {}

# Map from label to duas that are tainted by that label.
# So when we update liveness, we know what duas might be invalidated.
dua_dependencies: dict[int, Dua] = {}

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

num_bugs_of_type = { Bug.type : 0 }

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


def record_injectable_bugs_at(bug_type: int, atp: AttackPoint, is_new_atp, db: LavaDatabase, extra_duas_prechosen: list):
    """
    Record injectable bugs at a given attack point (atp) of a given type (bug_type).
    """
    skip_trigger_lvals = []
    if not is_new_atp:
        # Query DB for lval_ids already used with this atp/type
        param = BugParam(atp_id=atp.id, type=bug_type)
        pq = db.session.lookup_query('atp-shortcut', param)
        if not pq:
            pq = db.session.prepare_query(
                'atp-shortcut',
                lambda buglval: buglval.atp == param.atp_id and buglval.type == param.type
            )
            db.session.cache_query(pq, param)
        result = pq.execute()
        skip_trigger_lvals = [row.trigger_lval for row in result]

    skip_trigger_lvals = sorted(skip_trigger_lvals)
    skip_it = 0
    num_extra_duas = Bug.num_extra_duas[bug_type] - len(extra_duas_prechosen)
    assert num_extra_duas >= 0
    prechosen_labels = []
    for extra in extra_duas_prechosen:
        merge_into(extra.all_labels, prechosen_labels)

    for lval_id, trigger_dua in recent_dead_duas.items():
        # Fast-forward skip_it so skip_trigger_lvals[skip_it] >= lval_id
        while skip_it < len(skip_trigger_lvals) and skip_trigger_lvals[skip_it] < lval_id:
            skip_it += 1
        if skip_it < len(skip_trigger_lvals) and skip_trigger_lvals[skip_it] == lval_id:
            continue

        selected = get_dua_dead_range(trigger_dua, prechosen_labels)
        if not selected or selected.size() < LAVA_MAGIC_VALUE_SIZE:
            continue

        trigger, _ = get_or_create(DuaBytes(trigger_dua, selected))
        extra_duas = list(extra_duas_prechosen)
        labels_so_far = list(prechosen_labels)
        merge_into(trigger.all_labels, labels_so_far)

        # Get list of duas observed before chosen trigger
        end_idx = next((i for i, dua in enumerate(recent_duas_by_instr) if dua.instr >= trigger_dua.instr), len(recent_duas_by_instr))
        begin_idx = 0
        distance = end_idx - begin_idx
        if num_extra_duas < distance:
            for _ in range(num_extra_duas):
                extra = None
                for tries in range(2):
                    idx = random.randint(begin_idx, end_idx - 1)
                    extra_dua = recent_duas_by_instr[idx]
                    selected = get_dua_dead_range(extra_dua, labels_so_far)
                    if not selected:
                        continue
                    extra, _ = get_or_create(DuaBytes(extra_dua, selected))
                    if disjoint(labels_so_far, extra.all_labels):
                        break
                if extra is None:
                    break
                extra_duas.append(extra)
                new_size = len(extra.all_labels) + len(labels_so_far)
                merge_into(extra.all_labels, labels_so_far)
                assert new_size == len(labels_so_far)
        if len(extra_duas) < Bug.num_extra_duas[bug_type]:
            continue
        if not trigger.dua.fake_dua:
            if not (len(labels_so_far) >= 4 * Bug.num_extra_duas[bug_type]):
                continue

        c_max_liveness = 0
        for l in trigger.all_labels:
            c_max_liveness = max(c_max_liveness, liveness[l])

        assert bug_type != Bug.RET_BUFFER or atp.type == AttackPoint.QUERY_POINT
        assert len(extra_duas) == Bug.num_extra_duas[bug_type]
        bug = Bug(bug_type, trigger, c_max_liveness, atp, extra_duas)
        db.session.persist(bug)
        num_bugs_of_type[bug_type] += 1

        global num_bugs_added_to_db, num_potential_bugs, num_potential_nonbugs
        num_bugs_added_to_db += 1
        if trigger_dua.fake_dua:
            num_potential_nonbugs += 1
        else:
            num_potential_bugs += 1


def attack_point_lval_usage(ple: dict, db: LavaDatabase, ind2str: dict):
    panda_log_entry_attack_point = ple["attackPoint"]
    ast_id = None

    if "astLocId" in panda_log_entry_attack_point["srcInfo"]:
        ast_id = int(panda_log_entry_attack_point["srcInfo"]["astLocId"], 0)
        print(f"attack point id = {ast_id}")

    si = panda_log_entry_attack_point["srcInfo"]
    # ignore duas in header files
    if is_header_file(si["filename"]):
        return

    print("ATTACK POINT")
    if len(recent_dead_duas) == 0:
        print("no duas yet -- discarding attack point")
        return

    print(f"{len(recent_dead_duas)} viable duas remain")
    assert "astLocId" in si
    ast_loc = ASTLoc.from_serialized(ind2str[ast_id])
    assert len(ast_loc.filename) > 0

    atp, is_new_atp = get_or_create(db, AttackPoint(ast_loc, int(panda_log_entry_attack_point["info"])))
    print(f"@ATP: {str(atp)}")

    # Don't decimate PTR_ADD bugs.
    attack_point_type = int(panda_log_entry_attack_point["info"], 0)
    if attack_point_type == AttackPoint.POINTER_WRITE:
        record_injectable_bugs_at(Bug.REL_WRITE, atp, is_new_atp, db, [])
        # fall through
    if attack_point_type in [AttackPoint.POINTER_READ]:
        record_injectable_bugs_at(Bug.PTR_ADD, atp, is_new_atp, db, [])
    elif attack_point_type == AttackPoint.PRINTF_LEAK:
        record_injectable_bugs_at(Bug.PRINTF_LEAK, atp, is_new_atp, db, [])
    elif attack_point_type == AttackPoint.MALLOC_OFF_BY_ONE:
        record_injectable_bugs_at(Bug.MALLOC_OFF_BY_ONE, atp, is_new_atp, db, [])
    db.session.commit()


def taint_query_pri(ple: dict, db: LavaDatabase, ind2str: list, inputfile: str):
    assert ple is not None
    tqh = ple["taintQueryPri"]
    assert tqh is not None

    # Limit lval size
    length = min(tqh["len"], max_lval)
    num_tainted = tqh["numTainted"]
    si = tqh["srcInfo"]
    if is_header_file(str(si["filename"])):
        return
    assert si is not None
    cs = tqh["callStack"]
    assert cs is not None
    instr = ple["instr"]
    print(f"TAINT QUERY HYPERCALL len={length} num_tainted={num_tainted}\n")

    all_labels = []
    c_max_tcn = 0
    c_max_card = 0

    with db.session.transaction():
        # Update unique taint sets
        for tq in tqh["taintQuery"]:
            if tq["uniqueLabelSet"]:
                update_unique_taint_sets(tq["uniqueLabelSet"], db)

        viable_byte = [None] * length
        byte_tcn = [0] * length

        print(f"considering taint queries on {len(tqh.taint_query)} bytes\n")

        is_dua = False
        is_fake_dua = False
        num_viable_bytes = 0

        if num_tainted >= LAVA_MAGIC_VALUE_SIZE:
            for tq in tqh.taint_query:
                offset = tq.offset
                if offset >= length:
                    continue
                print(f"considering offset = {offset}\n")
                ls = ptr_to_labelset[int(tq["ptr"])]
                byte_tcn[offset] = tq.tcn

                current_byte_not_ok = 0
                current_byte_not_ok |= (tq.tcn > max_tcn) << CBNO_TCN_BIT
                current_byte_not_ok |= (len(ls.labels) > max_card) << CBNO_CRD_BIT
                if current_byte_not_ok:
                    print(f"discarding byte -- here's why: {current_byte_not_ok:x}\n")
                    if 1 << CBNO_TCN_BIT:
                        print("** tcn too high")
                    if 1 << CBNO_CRD_BIT:
                        print("** card too high")
                else:
                    print("retaining byte\n")
                    c_max_tcn = max(tq.tcn, c_max_tcn)
                    c_max_card = max(len(ls.labels), c_max_card)
                    merge_into(ls.labels, all_labels)
                    print(f"keeping byte @ offset {offset}\n")
                    viable_byte[offset] = ls
                    num_viable_bytes += 1

            print(f"{num_viable_bytes} viable bytes in lval\n")
            if (num_viable_bytes >= LAVA_MAGIC_VALUE_SIZE and
                len(all_labels) >= LAVA_MAGIC_VALUE_SIZE and
                get_dead_range(viable_byte, []).size() >= LAVA_MAGIC_VALUE_SIZE):
                is_dua = True

        if not is_dua and tqh["len"] - num_tainted >= LAVA_MAGIC_VALUE_SIZE:
            print("not enough taint -- what about non-taint?\n")
            print(f"len={length} num_tainted={num_tainted}\n")
            viable_byte = [None] * len(viable_byte)
            count = 0
            tqp = iter(tqh.taint_query)
            tqp_end = len(tqh.taint_query)
            for i in range(len(viable_byte)):
                try:
                    tq = next(tqp)
                except StopIteration:
                    tq = None
                if not tq or tq.offset > i or not tq.ptr:
                    # Use a static fake label set
                    if not hasattr(taint_query_pri, "_fake_ls"):
                        taint_query_pri._fake_ls = get_or_create(db, LabelSet(0, FAKE_DUA_BYTE_FLAG, "fakedua", []))
                    viable_byte[i] = taint_query_pri._fake_ls
                    count += 1
                if count >= LAVA_MAGIC_VALUE_SIZE:
                    break
            assert count >= LAVA_MAGIC_VALUE_SIZE
            is_fake_dua = True

        print(f"is_dua={int(is_dua)} is_fake_dua={int(is_fake_dua)}\n")
        assert not (is_dua and is_fake_dua)
        if is_dua or is_fake_dua:
            assert si.has_ast_loc_id
            ast_loc = ASTLoc.from_serialized(ind2str[si.ast_loc_id])
            assert len(ast_loc.filename) > 0

            lval, _ = get_or_create(SourceLval(ast_loc, si["astnodename"], length))
            dua, _ = get_or_create(Dua(lval, viable_byte, byte_tcn, all_labels, inputfile,
                             c_max_tcn, c_max_card, instr, is_fake_dua))

            if is_dua:
                for l in dua.all_labels:
                    dua_dependencies.setdefault(l, set()).add(dua)

            pad_atp, is_new_atp = get_or_create(db, AttackPoint(ast_loc, AttackPoint.QUERY_POINT))
            if length >= 20 and decimate_by_type(Bug.RET_BUFFER):
                range_ = get_dua_exploit_pad(dua)
                dua_bytes, _ = get_or_create(DuaBytes(dua, range_))
                if is_fake_dua or range_.size() >= 20:
                    record_injectable_bugs_at(Bug.RET_BUFFER, pad_atp, is_new_atp, [dua_bytes])

            print("OK DUA.\n")

            lval_id = lval.id
            if lval_id not in recent_dead_duas:
                recent_dead_duas[lval_id] = dua
                print("new lval\n")
            else:
                old_dua = recent_dead_duas[lval_id]
                instr_range = [i for i, d in enumerate(recent_duas_by_instr) if d == old_dua]
                if instr_range:
                    recent_duas_by_instr.pop(instr_range[0])
                for l in old_dua.all_labels:
                    dua_dependencies[l].discard(old_dua)
                recent_dead_duas[lval_id] = dua
                print("previously observed lval\n")

            if not recent_duas_by_instr or dua.instr >= recent_duas_by_instr[-1].instr:
                recent_duas_by_instr.append(dua)
            else:
                recent_duas_by_instr.append(dua)  # For simplicity, append

            assert len(recent_dead_duas) == len(recent_duas_by_instr)

            global num_real_duas, num_fake_duas
            if is_dua:
                num_real_duas += 1
            if is_fake_dua:
                num_fake_duas += 1
        else:
            print(f"discarded {num_viable_bytes} viable bytes {len(all_labels)} labels {si.filename}:{si.linenum} {si.astnodename}")


def get_or_create(project: dict, model, defaults: dict=None, **kwargs):
    """
    Retrieves an object from the database, or creates it if it does not exist.
    This function mimics the C++ `create_full` behavior.

    :param project: The dictionary storing arguments used to make LavaDatabase connections.
    :param model: The SQLAlchemy model class (e.g., SourceLval, AttackPoint).
    :param defaults: A dictionary of default values to set on the object
                     if it needs to be created. These are not used for querying.
                     If the object is created, kwargs are also used for creation.
    :param kwargs: Keyword arguments that represent the unique attributes
                   to query for the existing object. For composite types,
                   these should map to the underlying *column* names (e.g.,
                   'loc_filename', 'loc_begin_line' for ASTLoc components).
    :return: A tuple (instance, created_boolean).
             instance: The existing or newly created object.
             created_boolean: True if the object was created, False if it existed.

    """
    with LavaDatabase(project) as db:
        instance = db.session.query(model).filter_by(**kwargs).first()
        if instance:
            return instance, False
        else:
            # If not found, prepare data for creation
            # Merge kwargs (for unique identification) and defaults (for other attributes)
            params = {**kwargs, **(defaults or {})}
            instance = model(**params)
            db.session.add(instance)
            try:
                db.session.commit()
                return instance, True
            except IntegrityError:
                db.session.rollback()
                # Race condition: Another process/thread created it
                # between our query and our commit. Try to fetch again.
                instance = db.session.query(model).filter_by(**kwargs).first()
                if instance:
                    return instance, False
                else:
                    # This should ideally not happen if kwargs are truly unique constraints.
                    # Re-raise or handle as a critical error.
                    raise


def update_unique_taint_sets(unique_label_set: dict, project: dict, inputfile: str):
    """
    Update the global mapping of unique taint sets based on the provided unique_label_set from PANDA Log.
    Args:
        unique_label_set: the Panda Log unique label set
        project: The input arguments and host.json input
        inputfile: the input file_name that caused the bug
    """
    pointer = int(unique_label_set["ptr"])

    # The Lookup Logic (Major Fix)
    # C++ was checking if the pointer existed.
    # Python dicts are Hash Maps. Lookups are O(1).
    if pointer not in ptr_to_labelset:
        # Ensure labels are integers (C++ did a conversion)
        labels = [int(x) for x in unique_label_set["label"]]

        # 3. Create and Insert
        # C++: create(LabelSet{0, p, inputfile, vec});
        # Assuming get_or_create logic handles the object creation/deduplication
        label_set, _ = get_or_create(project, LabelSet(0, pointer, inputfile, labels))
        ptr_to_labelset[pointer] = label_set

    # Note: len() on a dict is O(1) in Python, unlike some C++ containers.
    if project['debug']:
        print(f"{len(ptr_to_labelset)} unique taint sets")


def update_liveness(panda_log_entry: dict, project: dict, inputfile: str):
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
        project (dict): Configuration dictionary containing project settings and database connections.
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
            update_unique_taint_sets(taint_query["uniqueLabelSet"], project, inputfile)
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
        if not is_dua_dead(dua):
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


def is_dua_dead(dua: Dua) -> bool:
    return get_dua_dead_range(dua, {}).size() == LAVA_MAGIC_VALUE_SIZE


def get_dua_dead_range(dua: Dua, to_avoid):
    viable_bytes = dua.viable_bytes
    print("checking viability of dua: currently %u viable bytes\n", count_nonzero(viable_bytes))
    if "nodua" in dua.lval.ast_name:
        print("Found nodua symbol, skipping")
        print(dua.lval.ast_name)
        print("\n")
        empty = Range(0, 0)
        return empty
    result = get_dead_range(dua.viable_bytes, to_avoid)
    print("%s\ndua has %u viable bytes\n", str(dua), result.size())
    return result


# get first 4-or-larger dead range. to_avoid is a sorted vector of labels that
# can't be used
def get_dead_range(viable_bytes: LabelSet, to_avoid):
    current_run = Range(0, 0)
    # NB: we have already checked dua for viability wrt tcn & card at induction
    # these do not need re-checking as they are to be captured at dua siphon point
    for i in range(len(viable_bytes.labels)):
        byte_viable = True
        ls = viable_bytes[i]
        if ls:
            if not disjoint(ls.labels, to_avoid):
                byte_viable = False
            else:
                for label in ls.labels:
                    if liveness[label] > max_liveness:
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


def main():
    """
    Main function for Find Bug Inject (FBI) tool.
    """
    if len(sys.argv) != 5 and len(sys.argv) != 6:
        print(f"Find Bug Inject (FBI)")
        print("usage: fbi host.json ProjectName pandalog inputfile [curtail count]")
        print("    Project JSON file may specify properties:")
        print("        max_liveness: Maximum liveness for DUAs")
        print("        max_cardinality: Maximum cardinality for label sets on DUAs")
        print("        max_tcn: Maximum taint compute number for DUAs")
        print("        max_lval_size: Maximum bytewise size for")
        print("    pandalog: Pandalog. Should be like queries-file-5.22-bash.iso.plog")
        print("    inputfile: Input file basename, like malware.pcap")
        sys.exit(1)

    curtail = int(sys.argv[5]) if len(sys.argv) == 6 else 0

    # We want decimation to be deterministic, so srand with magic value.
    random.seed(0x6c617661)
    host_json = sys.argv[1]
    project_name = sys.argv[2]
    panda_log = sys.argv[3]

    # host_json reads overall config from host.json, project_name finds configs for specific project
    project = parse_vars(host_json, project_name)

    root_directory = project["output_dir"]
    directory = f"{root_directory}/{project_name}"

    lavadb = f"{directory}/lavadb"

    # maps from ind -> (filename, lvalname, attackpointname)
    ind2str = load_idb(lavadb)
    print(f"{len(ind2str)} strings in lavadb")

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
            curtail = 0
        else:
            curtail = project.get("curtail_fbi", 0)
    print(f"Curtail is {curtail}")

    inputfile = sys.argv[4]

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

    # re-read pandalog, this time focusing on taint queries. Look for
    # dead available data, attack points, and thus bug injection opportunities
    with open(panda_log, 'r') as plog_file:
        plog_data = json.load(plog_file)

    num_entries_read = 0

    for ple in plog_data:
        num_entries_read += 1
        if num_entries_read % 10000 == 0:
            print(f"processed {num_entries_read} pandalog entries")
            print(f"{num_bugs_added_to_db} added to db {len(recent_dead_duas)} current duas {num_real_duas} real duas {num_fake_duas} fake duas")

        if "taintQueryPri" in ple:
            taint_query_pri(ple, project, ind2str, inputfile)
        elif "taintedBranch" in ple:
            update_liveness(ple, project, inputfile)
        elif "attackPoint" in ple:
            attack_point_lval_usage(ple, project, ind2str, inputfile)
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
    main()