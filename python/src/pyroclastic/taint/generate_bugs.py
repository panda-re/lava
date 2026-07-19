import random
import logging
from pyroclastic.utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, LavaDatabase, BugKind, AtpExecution, AtpKind, DuaInjectionPad, LivenessSnapshot, Range
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


def generate_magic() -> int:
    """Generates the 4-byte magic trigger value."""
    c_magic = 0
    for _ in range(4):
        c_magic <<= 8
        val = (random.randint(0, 32767) % 26) + 0x60
        c_magic |= val
        if random.randint(0, 32767) & 0x20:
            c_magic ^= 0x20
    return c_magic


def get_or_create_dua_bytes(db: LavaDatabase, cache: dict, dua: Dua, r: Range) -> DuaBytes:
    """Converts a Range into a DuaBytes record and caches it."""
    cache_key = (dua.id, r.low, r.high)
    if cache_key in cache:
        return cache[cache_key]

    # Extract labels based on the given range
    labels = set()
    for i in range(r.low, r.high):
        if dua.viable_bytes[i] is not None:
            labels.update(dua.viable_bytes[i].labels)

    d_bytes = get_or_create(
        db.session,
        DuaBytes,
        dua=dua.id,
        selected=r,
        defaults={'all_labels': list(labels)}
    )
    db.session.add(d_bytes)
    db.session.flush()
    cache[cache_key] = d_bytes
    return d_bytes


def get_max_liveness(db: LavaDatabase, inputfile: str, trigger: DuaBytes) -> int:
    c_max_liveness: int = 0
    if trigger.all_labels:
        # Query the liveness counts (stored in death_instr) for all labels in the trigger
        liveness_records = db.session.query(LivenessSnapshot.death_instr).filter(
            LivenessSnapshot.inputfile == inputfile,
            LivenessSnapshot.label.in_(trigger.all_labels)
        ).all()

        if liveness_records:
            # SQLAlchemy specific-column queries return tuples, so we extract index 0
            c_max_liveness = max([record[0] for record in liveness_records])
    return c_max_liveness


def record_injectable_bugs_offline(project_data: dict):
    """
    Streamlined bug generation using pre-computed DuaInjectionPads, mapped directly to match the C++ FBI generation.
    """
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache = {}
        seen_bug_signatures = set()

        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr).all()

            for exec_event in executions:
                atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))

                # Fetch available pads and DUAs for this execution context
                available_duas = db.session.query(Dua).filter(
                    Dua.inputfile == inputfile, Dua.instr <= exec_event.instr
                ).all()

                available_pads = db.session.query(DuaInjectionPad).join(Dua).filter(
                    Dua.inputfile == inputfile, Dua.instr <= exec_event.instr
                ).all()

                if not available_pads and not available_duas:
                    continue

                # Process combinations for valid targets
                for bug_type in target_bug_kinds:
                    num_extra = NUM_EXTRA_DUAS[bug_type]

                    # --- 1. Process Bugs Requiring Pads (Chaff with Extra DUAs & RET_BUFFER) ---
                    if bug_type in [BugKind.BUG_CHAFF_STACK_CONST, BugKind.BUG_CHAFF_HEAP_CONST,
                                    BugKind.BUG_CHAFF_DIVZERO, BugKind.BUG_RET_BUFFER]:

                        pad_kind = BugKind.BUG_RET_BUFFER if bug_type == BugKind.BUG_RET_BUFFER else BugKind.BUG_CHAFF_STACK_CONST
                        applicable_pads = [p for p in available_pads if p.bug_kind == pad_kind]

                        for pad in applicable_pads:
                            # 1. Fetch the Pad (This serves as the EXTRA DUA)
                            extra_dua_obj = db.session.query(Dua).get(pad.dua_id)
                            extra_trigger = get_or_create_dua_bytes(db, dua_bytes_cache, extra_dua_obj, pad.pad_range)

                            # 2. Iterate over ALL available DUAs to act as the main TRIGGER
                            for dua in available_duas:
                                sig = (atp.id, bug_type.value, dua.lval)

                                if sig in seen_bug_signatures:
                                    continue

                                r = get_dua_dead_range(dua, [], project_data)
                                if r.empty():
                                    continue

                                seen_bug_signatures.add(sig)
                                trigger = get_or_create_dua_bytes(db, dua_bytes_cache, dua, r)
                                c_max_liveness = get_max_liveness(db, inputfile, trigger)

                                b = Bug(
                                    bug_type=bug_type,
                                    trigger=trigger,
                                    trigger_lval=dua.lval,
                                    max_liveness=c_max_liveness,
                                    atp=atp,
                                    extra_duas=[extra_trigger.id],  # Use the pad as the extra dependency
                                    stackoff=0 if bug_type == BugKind.BUG_RET_BUFFER else (
                                        atp.stack_offset if hasattr(atp, 'stack_offset') else 0)
                                )
                                db.session.add(b)

                    # --- 2. Process CHAFF_STACK_UNUSED (Requires 0 Extra DUAs) ---
                    elif bug_type == BugKind.BUG_CHAFF_STACK_UNUSED:
                        for dua in available_duas:
                            sig = (atp.id, bug_type.value, dua.lval)

                            if sig in seen_bug_signatures:
                                continue

                            r = get_dua_dead_range(dua, [], project_data)
                            if r.empty():
                                continue

                            seen_bug_signatures.add(sig)
                            trigger = get_or_create_dua_bytes(db, dua_bytes_cache, dua, r)
                            c_max_liveness = get_max_liveness(db, inputfile, trigger)

                            b = Bug(
                                bug_type=bug_type,
                                trigger=trigger,
                                trigger_lval=dua.lval,
                                max_liveness=c_max_liveness,
                                atp=atp,
                                extra_duas=[],
                                stackoff=atp.stack_offset if hasattr(atp, 'stack_offset') else 0
                            )
                            db.session.add(b)

                    # --- 3. Process Standard Pointer Bugs ---
                    else:
                        for dua in available_duas:
                            sig = (atp.id, bug_type.value, dua.lval)

                            if sig in seen_bug_signatures:
                                continue
                            seen_bug_signatures.add(sig)
                            r = get_dua_dead_range(dua, [], project_data)
                            if r.empty():
                                continue

                            trigger = get_or_create_dua_bytes(db, dua_bytes_cache, dua, r)
                            c_max_liveness = get_max_liveness(db, inputfile, trigger)

                            b = Bug(
                                bug_type=bug_type,
                                trigger=trigger,
                                trigger_lval=dua.lval,
                                max_liveness=c_max_liveness,
                                atp=atp,
                                extra_duas=[],
                                stackoff=atp.stack_offset if hasattr(atp, 'stack_offset') else 0
                            )
                            db.session.add(b)

        # Persist all bug records atomically
        db.session.commit()


def print_phase2_stats(project_data: dict, debug: bool = False):
    """Dumps the entities specifically created/managed around Phase II."""
    with LavaDatabase(project_data) as db:
        session = db.session
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
