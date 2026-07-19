import random
import logging
from pyroclastic.utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, LavaDatabase, BugKind, AtpExecution, AtpKind, LivenessSnapshot, Range
from pyroclastic.taint.find_bug_injection import dump_table, get_dua_dead_range, get_or_create

logger = logging.getLogger(__name__)

# Define extra DUA requirements per bug type
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

RANDOM_DUA_TRIES = 2

def get_bug_kinds_for_atp(atp_kind: AtpKind) -> list[BugKind]:
    """Map Attack Point types to the bugs they can trigger."""
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


def merge_into(source_labels, target_set: set):
    """Emulates C++ std::set_union behavior in-place."""
    target_set.update(source_labels)


def disjoint(labels_a, labels_b) -> bool:
    """Checks if two iterables of labels have no intersection."""
    return set(labels_a).isdisjoint(labels_b)


def get_or_create_dua_bytes(db: LavaDatabase, cache: dict, dua: Dua, r: Range) -> DuaBytes:
    """Converts a Range into a DuaBytes record and caches it."""
    cache_key = (dua.id, r.low, r.high)
    if cache_key in cache:
        return cache[cache_key]

    labels = set()
    for i in range(r.low, r.high):
        if dua.viable_bytes[i] is not None:
            labels.update(dua.viable_bytes[i].labels)

    d_bytes = get_or_create(
        db.session,
        DuaBytes,
        dua=dua.id,
        selected=r,
        defaults={'all_labels': sorted(list(labels))}
    )
    db.session.add(d_bytes)
    db.session.flush()
    cache[cache_key] = d_bytes
    return d_bytes


def get_max_liveness(db: LavaDatabase, inputfile: str, trigger: DuaBytes) -> int:
    c_max_liveness: int = 0
    if trigger.all_labels:
        liveness_records = db.session.query(LivenessSnapshot.death_instr).filter(
            LivenessSnapshot.inputfile == inputfile,
            LivenessSnapshot.label.in_(trigger.all_labels)
        ).all()
        if liveness_records:
            c_max_liveness = max([record[0] for record in liveness_records])
    return c_max_liveness


def record_injectable_bugs_offline(project_data: dict):
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache = {}
        # Mimics the C++ atp-shortcut prepared query for skipping lval/atp/type repeats
        seen_bug_signatures = set()

        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr).all()

            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))

                # Fetch all DUAs available up to this point in execution
                available_duas = db.session.query(Dua).filter(
                    Dua.inputfile == inputfile, Dua.instr <= exec_event.instr
                ).order_by(Dua.instr).all()

                if not available_duas:
                    continue

                # Fetch prechosen offline pads (created in Phase I)
                prechosen_pads = db.session.query(DuaBytes).join(Dua).filter(
                    Dua.inputfile == inputfile, Dua.instr <= exec_event.instr
                ).all()

                for bug_type in target_bug_kinds:
                    num_extra_duas = NUM_EXTRA_DUAS[bug_type]

                    # If this bug type requires an exploit pad (RET_BUFFER / CHAFF)
                    if bug_type in [BugKind.BUG_CHAFF_STACK_CONST, BugKind.BUG_CHAFF_HEAP_CONST,
                                    BugKind.BUG_CHAFF_DIVZERO, BugKind.BUG_RET_BUFFER]:
                        
                        for pad in prechosen_pads:
                            prechosen_labels = set(pad.all_labels)
                            
                            for trigger_dua in available_duas:
                                sig = (atp.id, bug_type.value, trigger_dua.lval)
                                if sig in seen_bug_signatures:
                                    continue

                                # Verify trigger disjointness against the pad
                                selected = get_dua_dead_range(trigger_dua, list(prechosen_labels), project_data)
                                if selected.empty():
                                    continue

                                trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)
                                
                                labels_so_far = set(prechosen_labels)
                                merge_into(trigger.all_labels, labels_so_far)

                                if not trigger_dua.fake_dua:
                                    if len(labels_so_far) < (4 * num_extra_duas):
                                        continue

                                seen_bug_signatures.add(sig)
                                c_max_liveness = get_max_liveness(db, inputfile, trigger)

                                b = Bug(
                                    bug_type=bug_type,
                                    trigger=trigger,
                                    trigger_lval=trigger_dua.lval,
                                    max_liveness=c_max_liveness,
                                    atp=atp,
                                    extra_duas=[pad.id],
                                    stackoff=0 if bug_type == BugKind.BUG_RET_BUFFER else getattr(atp, 'stack_offset', 0)
                                )
                                db.session.add(b)

                    # Standard pointer bugs and Unused Chaff (Dynamic extra DUAs)
                    else:
                        for trigger_dua in available_duas:
                            sig = (atp.id, bug_type.value, trigger_dua.lval)
                            if sig in seen_bug_signatures:
                                continue

                            selected = get_dua_dead_range(trigger_dua, [], project_data)
                            if selected.empty():
                                continue

                            trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)
                            
                            extra_duas = []
                            labels_so_far = set()
                            merge_into(trigger.all_labels, labels_so_far)

                            # C++ std::distance check: do we have enough prior DUAs?
                            trigger_index = available_duas.index(trigger_dua)
                            if num_extra_duas <= trigger_index:
                                for _ in range(num_extra_duas):
                                    extra = None
                                    for tries in range(RANDOM_DUA_TRIES):
                                        # Faithfully mimicking the LAVA C++ `std::advance(it, 0)` bug
                                        extra_dua = available_duas[0]
                                        
                                        extra_selected = get_dua_dead_range(extra_dua, list(labels_so_far), project_data)
                                        if extra_selected.empty():
                                            continue
                                            
                                        candidate_extra = get_or_create_dua_bytes(db, dua_bytes_cache, extra_dua, extra_selected)
                                        if disjoint(labels_so_far, candidate_extra.all_labels):
                                            extra = candidate_extra
                                            break
                                            
                                    if extra is None:
                                        break
                                        
                                    extra_duas.append(extra)
                                    merge_into(extra.all_labels, labels_so_far)

                            if len(extra_duas) < num_extra_duas:
                                continue

                            if not trigger_dua.fake_dua:
                                if len(labels_so_far) < (4 * num_extra_duas):
                                    continue

                            seen_bug_signatures.add(sig)
                            c_max_liveness = get_max_liveness(db, inputfile, trigger)

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
        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))
        print("total bug:", db.session.query(Bug).count())

        try:
            # Sort by low, then high, then the DUA foreign key
            # to break any ties deterministically
            dua_bytes = session.query(DuaBytes).order_by(
                DuaBytes._low,
                DuaBytes._high,
                DuaBytes.dua
            ).all()
        except Exception:
            dua_bytes = db.session.query(DuaBytes).all()

        if debug:
            dump_table("DUA BYTES", dua_bytes, ['id', 'dua', 'selected'])
        else:
            print("dua_bytes:", len(dua_bytes))

        try:
            bugs = db.session.query(Bug).order_by(Bug.id).all()
        except Exception:
            bugs = db.session.query(Bug).all()

        if debug:
            dump_table("BUGS", bugs, ['id', 'type', 'trigger', 'trigger_lval', 'atp', 'max_liveness', 'extra_duas', 'stackoff'])
        else:
            print("bugs:", len(bugs))
