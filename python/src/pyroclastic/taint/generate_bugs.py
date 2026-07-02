import random
from typing import Optional
from sqlalchemy.orm import Session
from pyroclastic.utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, Range, LavaDatabase, BugKind, LivenessSnapshot, AtpExecution, AtpKind
from pyroclastic.taint.find_bug_injection import dump_table

LAVA_MAGIC_VALUE_SIZE = 4

# [C++ Alignment: Map to determine the extra padding required for specific exploits]
PAD_REQUIREMENTS = {
    BugKind.BUG_PTR_ADD: 0,
    BugKind.BUG_RET_BUFFER: 20,
    BugKind.BUG_REL_WRITE: 8,
    BugKind.BUG_PRINTF_LEAK: 0,
    BugKind.BUG_MALLOC_OFF_BY_ONE: 0
}

def get_bug_kinds_for_atp(atp_kind: AtpKind) -> list[BugKind]:
    """[C++ Alignment: Simulates case fallthrough for POINTER_WRITE]"""
    mapping = {
        AtpKind.POINTER_WRITE: [BugKind.BUG_REL_WRITE, BugKind.BUG_PTR_ADD],
        AtpKind.POINTER_READ: [BugKind.BUG_PTR_ADD],
        AtpKind.FUNCTION_ARG: [BugKind.BUG_PTR_ADD],
        AtpKind.PRINTF_LEAK: [BugKind.BUG_PRINTF_LEAK],
        AtpKind.MALLOC_OFF_BY_ONE: [BugKind.BUG_MALLOC_OFF_BY_ONE],
        AtpKind.QUERY_POINT: [BugKind.BUG_RET_BUFFER]
    }
    return mapping.get(atp_kind, [])

def disjoint(labels_a: list[int], labels_b: list[int]) -> bool:
    return set(labels_a).isdisjoint(set(labels_b))

def get_offline_dead_range(dua: Dua, liveness_map: dict, atp_instr: int) -> tuple[Range, int]:
    """Calculates if taint bytes are safely dead relative to the global PANDA clock."""
    start_idx = -1
    max_liveness = 0
    valid_length = 0
    best_range = Range(low=0, high=0)
    
    for i, ls in enumerate(dua.viable_bytes):
        if ls is None:
            if start_idx == -1:
                start_idx = i
            valid_length += 1
        else:
            is_dead = True
            for label in ls.labels:
                death_instr = liveness_map.get(label, 0)
                if death_instr >= atp_instr:
                    is_dead = False
                    break
                max_liveness = max(max_liveness, death_instr)
            
            if is_dead:
                if start_idx == -1: start_idx = i
                valid_length += 1
            else:
                start_idx = -1
                valid_length = 0

        if valid_length > (best_range.high - best_range.low):
            best_range = Range(low=start_idx, high=start_idx + valid_length)
            
    return best_range, max_liveness

def extract_labels_from_range(dua: Dua, selected: Range) -> list[int]:
    labels = set()
    for i in range(selected.low, selected.high):
        if dua.viable_bytes[i] is not None:
            labels.update(dua.viable_bytes[i].labels)
    return list(labels)

def generate_magic() -> int:
    c_magic = 0
    for _ in range(4):
        c_magic <<= 8
        # rand() % 26 + 0x60 generates '`' through 'z' (ish)
        val = (random.randint(0, 32767) % 26) + 0x60
        c_magic |= val
        # rand() & 0x20 checks a specific bit to maybe flip case
        if random.randint(0, 32767) & 0x20:
            c_magic ^= 0x20  # Flip bit
    return c_magic


def record_injectable_bugs_offline(project_data: dict, allow_cross_file: bool = False):
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        # --- 1. HOIST CACHE TO THE ABSOLUTE TOP ---
        # This guarantees it persists across ALL files, ALL executions, and ALL bug kinds!
        dua_bytes_cache = {}

        # Pre-populate from DB just in case we are doing incremental runs
        existing_dua_bytes = db.session.query(DuaBytes).all()
        for db_obj in existing_dua_bytes:
            # Safely extract the ID depending on how your ORM relationship is named
            d_id = db_obj.dua_id if hasattr(db_obj, 'dua_id') else db_obj.dua
            cache_key = (d_id, db_obj.selected.low, db_obj.selected.high)
            dua_bytes_cache[cache_key] = db_obj

        # 2. Pre-cache liveness timelines
        all_liveness_maps = {}
        for fname in file_list:
            snapshots = db.session.query(LivenessSnapshot).filter_by(inputfile=fname).all()
            all_liveness_maps[fname] = {s.label: s.death_instr for s in snapshots}

        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr).all()
            print(f"  [-] Found {len(executions)} ATP Executions in {inputfile}")

            seen_bug_combos = set()

            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))

                dua_query = db.session.query(Dua).filter(Dua.instr < exec_event.instr)
                if not allow_cross_file:
                    dua_query = dua_query.filter(Dua.inputfile == inputfile)
                valid_duas = dua_query.order_by(Dua.instr.desc()).all()

                stats = {
                    "no_pad": 0,
                    "duplicate": 0,
                    "liveness_too_small": 0,
                    "not_disjoint": 0,
                    "success": 0
                }

                for bug_kind in target_bug_kinds:
                    required_pad_size = PAD_REQUIREMENTS.get(bug_kind, 0)

                    pad_dua: Optional[Dua] = None
                    p_selected: Optional[Range] = None

                    if required_pad_size > 0:
                        for p_dua in valid_duas:
                            native_pad_map = all_liveness_maps.get(p_dua.inputfile, {})
                            p_range, _ = get_offline_dead_range(p_dua, native_pad_map, exec_event.instr)
                            if p_range.size() >= required_pad_size:
                                pad_dua = p_dua
                                p_selected = Range(low=p_range.low, high=p_range.low + required_pad_size)
                                break
                        if not pad_dua:
                            stats["no_pad"] += 1
                            continue

                    for trigger_dua in valid_duas:
                        combo_key = (atp.id, bug_kind.value, trigger_dua.lval)
                        if combo_key in seen_bug_combos:
                            stats["duplicate"] += 1
                            continue

                        if pad_dua and trigger_dua.id == pad_dua.id:
                            continue

                        native_trigger_map = all_liveness_maps.get(trigger_dua.inputfile, {})
                        t_range, max_liveness = get_offline_dead_range(trigger_dua, native_trigger_map,
                                                                       exec_event.instr)

                        if t_range.size() < LAVA_MAGIC_VALUE_SIZE:
                            stats["liveness_too_small"] += 1
                            continue

                        t_selected = Range(low=t_range.low, high=t_range.low + LAVA_MAGIC_VALUE_SIZE)
                        trigger_labels = extract_labels_from_range(trigger_dua, t_selected)

                        extra_duas = []
                        if pad_dua is not None and p_selected is not None:
                            pad_labels = extract_labels_from_range(pad_dua, p_selected)
                            if not disjoint(trigger_labels, pad_labels):
                                stats["not_disjoint"] += 1
                                continue

                            # --- PAD CACHE CHECK ---
                            p_cache_key = (pad_dua.id, p_selected.low, p_selected.high)
                            if p_cache_key in dua_bytes_cache:
                                pad_bytes = dua_bytes_cache[p_cache_key]
                            else:
                                pad_bytes = DuaBytes(dua=pad_dua.id, selected=p_selected, all_labels=pad_labels)
                                db.session.add(pad_bytes)
                                db.session.flush()
                                dua_bytes_cache[p_cache_key] = pad_bytes

                            extra_duas.append(pad_bytes.id)

                        # --- TRIGGER CACHE CHECK ---
                        t_cache_key = (trigger_dua.id, t_selected.low, t_selected.high)
                        if t_cache_key in dua_bytes_cache:
                            trigger_bytes = dua_bytes_cache[t_cache_key]
                        else:
                            trigger_bytes = DuaBytes(dua=trigger_dua.id, selected=t_selected, all_labels=trigger_labels)
                            db.session.add(trigger_bytes)
                            db.session.flush()
                            dua_bytes_cache[t_cache_key] = trigger_bytes

                        # --- PERSIST BUG ---
                        bug = Bug(
                            bug_type=bug_kind.value,
                            trigger=trigger_bytes.id,
                            trigger_lval=trigger_dua.lval,
                            atp=atp.id,
                            max_liveness=max_liveness,
                            magic=generate_magic(),
                            extra_duas=extra_duas
                        )
                        db.session.add(bug)
                        seen_bug_combos.add(combo_key)
                        stats["success"] += 1

                if valid_duas:
                    print(
                        f"    [>] ATP {atp.id} @ instr {exec_event.instr} | Targets: {[k.name for k in target_bug_kinds]} | Valid DUAs: {len(valid_duas)}")
                    print(
                        f"        Success: {stats['success']} | No Pad: {stats['no_pad']} | Taint Dead Too Soon: {stats['liveness_too_small']} | Overlapping Taints: {stats['not_disjoint']} | Deduped: {stats['duplicate']}")
                else:
                    print("No Valid DUAs found!")

        db.session.commit()
        print("[+] Offline bug generation successfully synchronized!")
        print_phase2_stats(project_data, db.session)


def print_phase2_stats(project_data: dict, session: Session):
    """Dumps the entities specifically created/managed around Phase II."""

    # 1. DUAs (Mined in Phase I, consumed in Phase II)
    try:
        duas = session.query(Dua).order_by(Dua.id).all()
    except Exception:
        duas = session.query(Dua).all()

    # 1. DuaBytes (Created exclusively during Phase II)
    try:
        dua_bytes = session.query(DuaBytes).order_by(DuaBytes.id).all()
    except Exception:
        dua_bytes = session.query(DuaBytes).all()

    if project_data.get("debug", False):
        # dump the selected range bounds and labels
        dump_table("DUA BYTES", dua_bytes, ['id', 'dua', 'selected'])
    else:
        print("dua_bytes:", len(dua_bytes))

    # 2. Bugs (Created exclusively during Phase II)
    try:
        bugs = session.query(Bug).order_by(Bug.id).all()
    except Exception:
        bugs = session.query(Bug).all()

    if project_data.get("debug", False):
        dump_table("BUGS", bugs, ['id', 'type', 'trigger', 'trigger_lval', 'atp', 'max_liveness', 'magic'])
    else:
        print("bugs:", len(bugs))
