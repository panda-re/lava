import random
from typing import Optional
from ..utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, Range, LavaDatabase, BugKind, LivenessSnapshot, AtpExecution, AtpKind

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
            if start_idx == -1: start_idx = i
            valid_length += 1
        else:
            is_dead = True
            for label in ls.labels:
                death_instr = liveness_map.get(label, 0)
                if death_instr > atp_instr:
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
    magic = 0
    for _ in range(4):
        magic <<= 8
        magic |= random.randint(0x60, 0x79)
        magic ^= (random.randint(0, 1) * 0x20)
    return magic

def record_injectable_bugs_offline(project_data: dict, allow_cross_file: bool = False):
    """
    Core Phase II Engine.
    Set allow_cross_file=True to pair a DUA from multiple files
    """
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]
        
        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        # Pre-cache all liveness timelines map per input file context
        all_liveness_maps = {}
        for file_name in file_list:
            snapshots = db.session.query(LivenessSnapshot).filter_by(inputfile=file_name).all()
            all_liveness_maps[file_name] = {s.label: s.death_instr for s in snapshots}

        # Loop through each input file execution context containing an ATP
        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(AtpExecution.instr).all()
            seen_bug_combos = set() 
            
            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))
                
                # Time travel validation: DUAs must be older than the current ATP event execution
                dua_query = db.session.query(Dua).filter(Dua.instr < exec_event.instr)
                
                # ENFORCING STRATEGY SWITCH:
                if not allow_cross_file:
                    dua_query = dua_query.filter(Dua.inputfile == inputfile)
                    
                valid_duas = dua_query.order_by(Dua.instr.desc()).all()

                for bug_kind in target_bug_kinds:
                    required_pad_size = PAD_REQUIREMENTS.get(bug_kind, 0)
                    
                    # --- STEP 1: Select Exploit Payload Pad ---
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
                            continue

                    # --- STEP 2: Find a valid Trigger Condition DUA ---
                    for trigger_dua in valid_duas:
                        combo_key = (atp.id, bug_kind.value, trigger_dua.lval)
                        if combo_key in seen_bug_combos:
                            continue
                        
                        if pad_dua and trigger_dua.id == pad_dua.id:
                            continue

                        # Query liveness map tied directly to the source file that birthed this specific DUA
                        native_trigger_map = all_liveness_maps.get(trigger_dua.inputfile, {})
                        t_range, max_liveness = get_offline_dead_range(trigger_dua, native_trigger_map, exec_event.instr)
                        if t_range.size() < LAVA_MAGIC_VALUE_SIZE:
                            continue

                        t_selected = Range(low=t_range.low, high=t_range.low + LAVA_MAGIC_VALUE_SIZE)
                        trigger_labels = extract_labels_from_range(trigger_dua, t_selected)

                        # --- STEP 3: Ensure disjoint taints ---
                        extra_duas = []
                        if pad_dua is not None and p_selected is not None:
                            pad_labels = extract_labels_from_range(pad_dua, p_selected)
                            if not disjoint(trigger_labels, pad_labels):
                                continue
                            
                            pad_bytes = DuaBytes(
                                dua=pad_dua.id,
                                selected=p_selected,
                                all_labels=pad_labels
                            )
                            db.session.add(pad_bytes)
                            db.session.flush()
                            extra_duas.append(pad_bytes.id)

                        trigger_bytes = DuaBytes(
                            dua=trigger_dua.id,
                            selected=t_selected,
                            all_labels=trigger_labels
                        )
                        db.session.add(trigger_bytes)
                        db.session.flush()

                        # --- STEP 4: Persist modern LAVA bug tuple ---
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

        db.session.commit()
        print("[+] Offline bug generation successfully synchronized!")
        count_bugs(project_data)


def count_bugs(project_data):
    with LavaDatabase(project_data) as db:
        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))

        print("total bug:", db.session.query(Bug).count())
        print("total DuaBytes:", db.session.query(DuaBytes).count())
