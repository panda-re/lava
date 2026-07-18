import random
import logging
from sqlalchemy.orm import Session
from typing import List, Set, Dict, Optional
from pyroclastic.utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, Range, LavaDatabase, BugKind, LivenessSnapshot, AtpExecution, AtpKind, SourceLval
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

logger = logging.getLogger(__name__)

def get_ret_buffer_pad_range(dua: Dua, required_size: int) -> Optional[Range]:
    """
    C++ Match: get_dua_exploit_pad logic.
    Bypasses liveness checking for RET_BUFFER pads because stack buffers
    are meant to be overwritten live at the exact moment of function return!
    """
    start_idx = -1
    valid_length = 0
    for i, ls in enumerate(dua.viable_bytes):
        if ls is not None:
            if start_idx == -1:
                start_idx = i
            valid_length += 1
            if valid_length >= required_size:
                return Range(low=start_idx, high=start_idx + required_size)
        else:
            start_idx = -1
            valid_length = 0
    return None


def get_bug_kinds_for_atp(atp_kind: AtpKind) -> list[BugKind]:
    """[C++ Alignment: Simulates case fallthrough for POINTER_WRITE]"""
    mapping = {
        AtpKind.POINTER_WRITE: [BugKind.BUG_REL_WRITE, BugKind.BUG_PTR_ADD],
        AtpKind.POINTER_READ: [BugKind.BUG_PTR_ADD],
        AtpKind.FUNCTION_ARG: [BugKind.BUG_PTR_ADD],
        AtpKind.PRINTF_LEAK: [BugKind.BUG_PRINTF_LEAK],
        AtpKind.MALLOC_OFF_BY_ONE: [BugKind.BUG_MALLOC_OFF_BY_ONE],
        AtpKind.QUERY_POINT: [BugKind.BUG_RET_BUFFER,
                              BugKind.BUG_CHAFF_STACK_CONST, BugKind.BUG_CHAFF_HEAP_CONST,
                              BugKind.BUG_CHAFF_DIVZERO, BugKind.BUG_CHAFF_DIVZERO]
    }
    return mapping.get(atp_kind, [])


def disjoint(labels_a: list[int], labels_b: list[int]) -> bool:
    return set(labels_a).isdisjoint(set(labels_b))


def get_offline_dead_range(dua: Dua, liveness_map: dict, atp_instr: int) -> tuple[Range, int]:
    """
    Calculates if taint bytes are safely dead relative to the global PANDA clock. (1:1 C++ Match)
    """
    max_liveness = 0
    # 1. Global Liveness Check: C++ calculates max_liveness across ALL viable bytes for this DUA
    for ls in dua.viable_bytes:
        if ls is not None:
            for label in ls.labels:
                death_instr = liveness_map.get(label, 0)
                max_liveness = max(max_liveness, death_instr)

    # 2. [C++: c_max_liveness < instr] - If ANY byte is alive at/after ATP, the whole DUA is dead to us!
    if max_liveness >= atp_instr:
        return Range(low=0, high=0), max_liveness

    # 3. Find the longest contiguous range of VALID (non-null) tainted bytes
    start_idx = -1
    valid_length = 0
    best_start = 0
    best_length = 0

    for i, ls in enumerate(dua.viable_bytes):
        if ls is not None:  # C++: if (val != 0 && val != FAKE_DUA_BYTE_FLAG)
            if start_idx == -1:
                start_idx = i
            valid_length += 1
        else:
            # A NULL byte breaks the contiguous chain!
            if valid_length > best_length:
                best_start = start_idx
                best_length = valid_length
            start_idx = -1
            valid_length = 0

    if valid_length > best_length:
        best_start = start_idx
        best_length = valid_length

    return Range(low=best_start, high=best_start + best_length), max_liveness


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


def get_or_create_dua_bytes(db: LavaDatabase, cache: dict, dua_id: int, selected_range: Range,
                            labels: list[int]) -> DuaBytes:
    """
    Helper to deduplicate DuaBytes generation cleanly.
    """
    cache_key = (dua_id, selected_range.low, selected_range.high)
    if cache_key in cache:
        return cache[cache_key]

    d_bytes = DuaBytes(dua=dua_id, selected=selected_range, all_labels=labels)
    db.session.add(d_bytes)
    db.session.flush()
    cache[cache_key] = d_bytes
    return d_bytes


def record_injectable_bugs_offline(project_data: dict, random_sampling_threshold: int = 2):
    """
    LAVA 1.0 implementation, identical bug mining steps to the C++ version.
    """
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache = {}
        existing_dua_bytes = db.session.query(DuaBytes).all()
        for db_obj in existing_dua_bytes:
            d_id = db_obj.dua_id if hasattr(db_obj, 'dua_id') else db_obj.dua
            cache_key = (d_id, db_obj.selected.low, db_obj.selected.high)
            dua_bytes_cache[cache_key] = db_obj

        all_liveness_maps = {}
        for file_name in file_list:
            snapshots = db.session.query(LivenessSnapshot).filter_by(inputfile=file_name).all()
            all_liveness_maps[file_name] = {s.label: s.death_instr for s in snapshots}

        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr).all()
            seen_bug_combos = set()

            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))

                # --- C++ FIX: Filter out fake_dua natively! ---
                dua_query = db.session.query(Dua).filter(
                    Dua.instr < exec_event.instr,
                    Dua.inputfile == inputfile
                )
                valid_duas = dua_query.order_by(Dua.instr.desc()).all()

                stats = {"no_pad": 0, "duplicate": 0, "liveness_too_small": 0, "not_disjoint": 0, "success": 0}

                # =====================================================================
                # CHAFF BUG GENERATION BLOCK
                # =====================================================================
                if atp.stack_offset != 0 and AtpKind(atp.type) == AtpKind.QUERY_POINT:
                    seen_lvals = set()
                    most_recent_duas = []
                    for d in valid_duas:
                        if d.lval not in seen_lvals:
                            seen_lvals.add(d.lval)
                            most_recent_duas.append(d)
                    valid_duas = most_recent_duas

                    viable_dead_duas = []
                    
                    # A. Find viable DEAD duas (Aligning with C++: Evaluate all for CHAFF_STACK_UNUSED)
                    for dua in valid_duas:
                        native_map = all_liveness_maps.get(dua.inputfile, {})
                        r, max_liveness = get_offline_dead_range(dua, native_map, exec_event.instr)
                        
                        # Only proceed if we have enough dead bytes for the LAVA magic value
                        if r.size() >= LAVA_MAGIC_VALUE_SIZE:
                            viable_dead_duas.append((dua, r, max_liveness))

                            # 1. CHAFF_STACK_UNUSED generated for EVERY viable DUA (Matches C++)
                            labels = extract_labels_from_range(dua, r)
                            dua_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, dua.id, r, labels)

                            bug_unused = Bug(
                                bug_type=BugKind.BUG_CHAFF_STACK_UNUSED.value,
                                trigger=dua_bytes.id,
                                trigger_lval=dua.lval,
                                atp=atp.id,
                                max_liveness=max_liveness,
                                magic=generate_magic(),
                                extra_duas=[]  # Explicitly supply empty extra_duas
                            )
                            db.session.add(bug_unused)
                            stats["success"] += 1

                    # B. Random Sampling Threshold for the remaining chaff variants (Match C++)
                    if len(viable_dead_duas) <= random_sampling_threshold:
                        selected_duas = viable_dead_duas
                    else:
                        selected_duas = random.sample(viable_dead_duas, random_sampling_threshold)

                    # C. Generate the 3 variant bugs for each randomly selected DUA
                    chaff_kinds = [
                        BugKind.BUG_CHAFF_STACK_CONST,
                        BugKind.BUG_CHAFF_HEAP_CONST,
                        BugKind.BUG_CHAFF_DIVZERO
                    ]

                    for dua, r, max_liveness in selected_duas:
                        labels = extract_labels_from_range(dua, r)
                        dua_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, dua.id, r, labels)

                        for c_kind in chaff_kinds:
                            c_bug = Bug(
                                bug_type=c_kind.value,
                                trigger=dua_bytes.id,
                                trigger_lval=dua.lval,
                                atp=atp.id,
                                max_liveness=max_liveness,
                                magic=generate_magic(),
                                extra_duas=[]  # Explicitly supply empty extra_duas
                            )
                            db.session.add(c_bug)
                            stats["success"] += 1

                # =====================================================================
                # STANDARD LAVA BUG GENERATION BLOCK
                # =====================================================================
                standard_bug_kinds = [k for k in target_bug_kinds if "CHAFF" not in k.name]
                for bug_kind in standard_bug_kinds:
                    required_pad_size = PAD_REQUIREMENTS.get(bug_kind, 0)
                    pad_dua: Optional[Dua] = None
                    p_selected: Optional[Range] = None

                    if bug_kind == BugKind.BUG_RET_BUFFER:
                        # --- RETROACTIVE TRAIT GRABBER ---
                        # 1. Get ALL lvals that share this physical location in the code
                        target_lvals = db.session.query(SourceLval).filter(
                            SourceLval.loc == atp.loc
                        ).all()

                        for target_lval in target_lvals:
                            # 2. Lock the DUA to this EXACT execution time!
                            # (lval, inputfile, instr, fake_dua) is a Unique Constraint,
                            # so .first() is now mathematically perfect.
                            pad_dua = db.session.query(Dua).filter_by(
                                lval=target_lval.id,
                                inputfile=inputfile,
                                instr=exec_event.instr,
                                fake_dua=False
                            ).first()

                            if pad_dua:
                                # 3. Bypass Liveness (Buffer is smashed LIVE on return!)
                                p_selected = get_ret_buffer_pad_range(pad_dua, required_pad_size)
                                if p_selected:
                                    break  # We successfully found our pad, stop checking lvals!

                        if not p_selected:
                            stats["no_pad"] += 1
                            continue

                    elif required_pad_size > 0:
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

                            # Clean, DRY Cache check!
                            pad_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, pad_dua.id, p_selected, pad_labels)
                            extra_duas.append(pad_bytes.id)

                        # Clean, DRY Cache check!
                        trigger_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua.id, t_selected,
                                                                trigger_labels)

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

        db.session.commit()
        print("[+] Offline bug generation successfully synchronized!")


def print_phase2_stats(project_data: dict, debug: bool = False):
    """
    Dumps the entities specifically created/managed around Phase II.
    """
    with LavaDatabase(project_data) as db:
        session = db.session
        # 1. Get a quick overview of count of Bug by Type found
        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))
        print("total bug:", db.session.query(Bug).count())

        # 2. DuaBytes (Created exclusively during Phase II)
        try:
            dua_bytes = session.query(DuaBytes).order_by(DuaBytes.id).all()
        except Exception:
            dua_bytes = session.query(DuaBytes).all()

        if debug:
            # dump the selected range bounds and labels
            dump_table("DUA BYTES", dua_bytes, ['id', 'dua', 'selected'])
        else:
            print("dua_bytes:", len(dua_bytes))

        # 3. Bugs (Created exclusively during Phase II)
        try:
            bugs = session.query(Bug).order_by(Bug.id).all()
        except Exception:
            bugs = session.query(Bug).all()

        if debug:
            dump_table("BUGS", bugs, ['id', 'type', 'trigger', 'trigger_lval', 'atp', 'max_liveness', 'magic'])
        else:
            print("bugs:", len(bugs))
