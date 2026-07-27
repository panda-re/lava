import logging
from typing import cast, Dict, Set
from pyroclastic.utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, LavaDatabase, BugKind, AtpExecution, AtpKind, LivenessSnapshot, Range
from pyroclastic.utils.funcs import dump_table
from pyroclastic.taint.taint_utils import get_dua_dead_range, disjoint, merge_into


logger = logging.getLogger(__name__)

# Derived from the implicit usage of `Bug::num_extra_duas[bug_type]` in `record_injectable_bugs_at`.
NUM_EXTRA_DUAS = {
    BugKind.BUG_PTR_ADD: 0,
    BugKind.BUG_RET_BUFFER: 1,
    BugKind.BUG_REL_WRITE: 2,
    BugKind.BUG_PRINTF_LEAK: 0,
    BugKind.BUG_MALLOC_OFF_BY_ONE: 0,
    BugKind.BUG_CHAFF_STACK_UNUSED: 0,
    BugKind.BUG_CHAFF_STACK_CONST: 1,
    BugKind.BUG_CHAFF_HEAP_CONST: 1,
    BugKind.BUG_CHAFF_DIVZERO: 1
}

# Derived from `#define RANDOM_DUA_TRIES 2` in the global scope of fbi.cpp.
RANDOM_DUA_TRIES = 2


def get_bug_kinds_for_atp(atp_kind: AtpKind) -> list[BugKind]:
    """
    Map Attack Point types to the bugs they can trigger.
    
    C++ Origin:
    Derived directly from the `switch` statement inside `attack_point_lval_usage()`[cite: 15].
    In C++, `AttackPoint::POINTER_WRITE` falls through to `POINTER_READ`, meaning it triggers both 
    `REL_WRITE` and `PTR_ADD`[cite: 15].
    """
    mapping = {
        AtpKind.POINTER_WRITE: [BugKind.BUG_REL_WRITE, BugKind.BUG_PTR_ADD],
        AtpKind.POINTER_READ: [BugKind.BUG_PTR_ADD],
        AtpKind.FUNCTION_ARG: [BugKind.BUG_PTR_ADD],
        AtpKind.PRINTF_LEAK: [BugKind.BUG_PRINTF_LEAK],
        AtpKind.MALLOC_OFF_BY_ONE: [BugKind.BUG_MALLOC_OFF_BY_ONE],
        AtpKind.QUERY_POINT: [
            BugKind.BUG_RET_BUFFER,
            BugKind.BUG_CHAFF_STACK_UNUSED,
            BugKind.BUG_CHAFF_STACK_CONST,
            BugKind.BUG_CHAFF_HEAP_CONST,
            BugKind.BUG_CHAFF_DIVZERO
        ]
    }
    return mapping.get(atp_kind, [])


def get_or_create_dua_bytes(db: LavaDatabase, cache: dict, dua: Dua, r: Range) -> DuaBytes:
    """Converts a Range into a DuaBytes record and caches it natively."""
    cache_key = (dua.id, r.low, r.high)
    if cache_key in cache:
        return cache[cache_key]

    labels = set()
    for i in range(r.low, r.high):
        if dua.viable_bytes[i] is not None:
            labels.update(dua.viable_bytes[i].labels)

    sorted_labels = sorted(list(labels))

    # Native SQLAlchemy replacement for get_or_create
    d_bytes = db.session.query(DuaBytes).filter_by(dua=dua.id, _low=r.low, _high=r.high).first()
    if not d_bytes:
        d_bytes = DuaBytes(dua=dua.id, selected=r, all_labels=sorted_labels)
        db.session.add(d_bytes)
        db.session.flush()

    cache[cache_key] = d_bytes
    return d_bytes


def get_max_liveness(offline_liveness: dict, trigger: DuaBytes) -> int:
    c_max_liveness = 0
    if trigger.all_labels:
        # Simply check the labels against our point-in-time dictionary
        c_max_liveness = max([offline_liveness.get(label, 0) for label in trigger.all_labels] + [0])
    return c_max_liveness


def get_dua_exploit_pad(dua: Dua, liveness: dict[int, int]) -> Range:
    # Use integers for tracking logic
    current_low, current_high = 0, 0
    largest_low, largest_high = 0, 0

    for i, ls in enumerate(dua.viable_bytes):
        label = cast(int, list(ls.labels)[0]) if (ls is not None and len(ls.labels) == 1) else None

        if (label is not None and
                dua.byte_tcn[i] == 0 and liveness.get(label, 0) <= 10):
            if current_high <= current_low:
                current_low, current_high = i, i + 1
            else:
                current_high += 1
        else:
            if (current_high - current_low) > (largest_high - largest_low):
                largest_low, largest_high = current_low, current_high
            current_low, current_high = 0, 0

    # Final check
    if (current_high - current_low) > (largest_high - largest_low):
        largest_low, largest_high = current_low, current_high

    # Reserve 4 bytes for trigger at start if the pad is large enough
    if (largest_high - largest_low) >= 20:
        largest_low += 4

    # Return frozen instances
    return Range(low=largest_low, high=largest_high)


def record_injectable_bugs_offline(project_data: dict):
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache: Dict[tuple, DuaBytes] = {}
        seen_bug_signatures: Set[tuple] = set()

        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr).all()

            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                liveness_records = db.session.query(LivenessSnapshot).filter(
                    LivenessSnapshot.inputfile == inputfile,
                    LivenessSnapshot.atp_instr == exec_event.instr
                ).all()

                offline_liveness: dict[int, int] = {r.label: r.liveness_count for r in liveness_records}

                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))

                # 1. Get all historical DUAs
                raw_duas = db.session.query(Dua).filter(
                    Dua.inputfile == inputfile, Dua.instr <= exec_event.instr,
                    (Dua.death_instr.is_(None) | (Dua.death_instr > exec_event.instr))
                ).order_by(Dua.instr.asc()).all()

                if not raw_duas:
                    continue

                # 2. Reconstruct the C++ overwrite behavior (Most Recent DUA)
                recent_duas_map = {}
                for d in raw_duas:
                    recent_duas_map[d.lval] = d

                # 3. Sort them back into execution order
                available_duas = sorted(recent_duas_map.values(), key=lambda x: x.instr)

                if not available_duas:
                    continue

                # --- NEW LOGIC: Dynamically build prechosen_pads ---
                prechosen_pads = []
                chaff_pads = []

                # Rather than build DuaBytes in Phase I, we can replicate the logic here
                for exploit_dua in available_duas:
                    # RET_BUFFER Pads (Requires length >= 20)
                    if getattr(exploit_dua, 'length', 0) >= 20:
                        # You can use get_dua_dead_range or port get_dua_exploit_pad here
                        r = get_dua_exploit_pad(exploit_dua, offline_liveness)
                        if exploit_dua.fake_dua or r.size() >= 20:
                            pad_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, exploit_dua, r)
                            prechosen_pads.append(pad_bytes)
                    
                    # CHAFF Pads (Sample up to RANDOM_SAMPLING_THRESHOLD = 2)
                    if len(chaff_pads) < RANDOM_DUA_TRIES:
                        r_chaff = get_dua_dead_range(exploit_dua, [], offline_liveness, project_data)
                        if not r_chaff.empty():
                            pad_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, exploit_dua, r_chaff)
                            chaff_pads.append(pad_bytes)
                    else:
                        # C++ strictly re-uses recent_duas_by_instr[0] when >= threshold
                        exploit_dua = available_duas[0]
                        r_chaff = get_dua_dead_range(exploit_dua, [], offline_liveness, project_data)
                        if not r_chaff.empty():
                            pad_bytes = get_or_create_dua_bytes(db, dua_bytes_cache, exploit_dua, r_chaff)
                            chaff_pads.append(pad_bytes)

                for bug_type in target_bug_kinds:
                    num_extra_duas = NUM_EXTRA_DUAS[bug_type]

                    # -------------------------------------------------------------
                    # Handle RET_BUFFER Bugs (1 Prechosen Pad, Range >= 20, Labels >= 4)
                    # -------------------------------------------------------------
                    if bug_type == BugKind.BUG_RET_BUFFER:
                        for pad in prechosen_pads:
                            prechosen_labels = set(pad.all_labels)

                            for trigger_dua in available_duas:
                                sig = (atp.id, bug_type.value, trigger_dua.lval)
                                if sig in seen_bug_signatures:
                                    continue

                                # 1. Dead range selection considering prechosen labels
                                selected = get_dua_dead_range(
                                    trigger_dua, list(prechosen_labels), offline_liveness, project_data
                                )
                                if selected.empty():
                                    continue

                                trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)

                                labels_so_far = set(prechosen_labels)
                                merge_into(set(trigger.all_labels), labels_so_far)

                                # 3. C++ Condition: labels_so_far >= 4 * num_extra_duas (4 * 1 = 4)
                                if not trigger_dua.fake_dua and len(labels_so_far) < 4:
                                    continue

                                seen_bug_signatures.add(sig)
                                c_max_liveness = get_max_liveness(offline_liveness, trigger)

                                b = Bug(
                                    bug_type=bug_type,
                                    trigger=trigger,
                                    trigger_lval=trigger_dua.lval,
                                    max_liveness=c_max_liveness,
                                    atp=atp,
                                    extra_duas=[pad.id],  # 1 extra DUA from prechosen_pads
                                    stackoff=getattr(atp, 'stack_offset', 0)
                                )
                                db.session.add(b)

                    # -------------------------------------------------------------
                    # Handle Chaff Bugs (1 Prechosen Pad, Labels >= 4)
                    # -------------------------------------------------------------
                    elif bug_type in [
                        BugKind.BUG_CHAFF_STACK_CONST, 
                        BugKind.BUG_CHAFF_HEAP_CONST, 
                        BugKind.BUG_CHAFF_DIVZERO
                    ]:
                        for pad in chaff_pads:
                            prechosen_labels = set(pad.all_labels)

                            for trigger_dua in available_duas:
                                sig = (atp.id, bug_type.value, trigger_dua.lval)
                                if sig in seen_bug_signatures:
                                    continue

                                selected = get_dua_dead_range(
                                    trigger_dua, list(prechosen_labels), offline_liveness, project_data
                                )
                                if selected.empty():
                                    continue

                                trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)

                                labels_so_far = set(prechosen_labels)
                                merge_into(set(trigger.all_labels), labels_so_far)

                                # C++ Condition: labels_so_far >= 4 * num_extra_duas (4 * 1 = 4)
                                if not trigger_dua.fake_dua and len(labels_so_far) < 4:
                                    continue

                                seen_bug_signatures.add(sig)
                                c_max_liveness = get_max_liveness(offline_liveness, trigger)

                                b = Bug(
                                    bug_type=bug_type,
                                    trigger=trigger,
                                    trigger_lval=trigger_dua.lval,
                                    max_liveness=c_max_liveness,
                                    atp=atp,
                                    extra_duas=[pad.id],
                                    stackoff=getattr(atp, 'stack_offset', 0)
                                )
                                db.session.add(b)

                    else:
                        for trigger_dua in available_duas:
                            sig = (atp.id, bug_type.value, trigger_dua.lval)
                            if sig in seen_bug_signatures:
                                continue

                            # Use the offline viability checker
                            selected = get_dua_dead_range(trigger_dua, [], offline_liveness, project_data)
                            if selected.empty():
                                continue

                            trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)

                            extra_duas = []
                            labels_so_far: set[int] = set()
                            merge_into(set(trigger.all_labels), labels_so_far)

                            trigger_index = available_duas.index(trigger_dua)
                            if num_extra_duas <= trigger_index:
                                for _ in range(num_extra_duas):
                                    extra = None
                                    for tries in range(RANDOM_DUA_TRIES):
                                        extra_dua = available_duas[0]

                                        # Use the offline viability checker
                                        extra_selected = get_dua_dead_range(extra_dua,
                                                                            list(labels_so_far),
                                                                            offline_liveness,
                                                                            project_data)
                                        if extra_selected.empty():
                                            continue

                                        candidate_extra = get_or_create_dua_bytes(db, dua_bytes_cache, extra_dua,
                                                                                  extra_selected)

                                        if disjoint(labels_so_far, candidate_extra.all_labels):
                                            extra = candidate_extra
                                            break

                                    if extra is None:
                                        break

                                    extra_duas.append(extra)
                                    merge_into(set(extra.all_labels), labels_so_far)

                            if len(extra_duas) < num_extra_duas:
                                continue

                            if not trigger_dua.fake_dua:
                                if len(labels_so_far) < (4 * num_extra_duas):
                                    continue

                            seen_bug_signatures.add(sig)
                            c_max_liveness = get_max_liveness(offline_liveness, trigger)

                            b = Bug(
                                bug_type=bug_type,
                                trigger=trigger,
                                trigger_lval=trigger_dua.lval,
                                max_liveness=c_max_liveness,
                                atp=atp,
                                extra_duas=[e.id for e in extra_duas],
                                stackoff=getattr(atp, 'stack_offset', 0)
                            )
                            db.session.add(b)

        db.session.commit()


def print_phase2_stats(project_data: dict, debug: bool = False):
    """
    Dumps the entities specifically created/managed around Phase II.
    """
    with LavaDatabase(project_data) as db:
        try:
            # Sort by low, then high, then the DUA foreign key
            # to break any ties deterministically
            dua_bytes = db.session.query(DuaBytes).order_by(
                DuaBytes._low,
                DuaBytes._high,
                DuaBytes.dua
            ).all()
        except Exception:
            dua_bytes = db.session.query(DuaBytes).all()

        if debug:
            dump_table("DUA BYTES", dua_bytes, ['dua', 'selected'])
        else:
            print("dua_bytes:", len(dua_bytes))

        try:
            # Sort deterministically by domain attributes to align diffs across Python and C++ runs
            bugs = db.session.query(Bug).order_by(
                Bug.type,
                Bug.atp,
                Bug.trigger,
                Bug.stackoff,
                Bug.id  # Final tie-breaker
            ).all()
        except Exception:
            bugs = db.session.query(Bug).all()

        if debug:
            dump_table("BUGS", bugs, ['type', 'trigger', 'trigger_lval', 'atp', 'max_liveness', 'extra_duas', 'stackoff'])
        else:
            print("bugs:", len(bugs))

        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))
        print("total bug:", db.session.query(Bug).count())
