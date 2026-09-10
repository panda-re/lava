import logging
import random
from typing import cast, Dict
import argparse
from ..utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, LavaDatabase, BugKind, AtpExecution, AtpKind, LivenessSnapshot, Range
from ..utils.funcs import dump_table
from ..taint.taint_utils import get_dua_dead_range, disjoint, merge_into
from ..utils.vars import parse_vars

logging.basicConfig(level=logging.INFO)
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


def _get_or_create_bug_like_cpp(
        db: LavaDatabase,
        dua_bytes_cache: Dict[tuple, DuaBytes],
        atp: AttackPoint,
        bug_type: BugKind,
        stackoff: int,
        available_duas: list[Dua],
        offline_liveness: dict[int, int],
        project_data: dict,
        is_new_atp: bool,
        extra_duas_prechosen: list[DuaBytes] | None = None):
    prechosen = extra_duas_prechosen or []
    num_extra_duas = NUM_EXTRA_DUAS[bug_type] - len(prechosen)
    if num_extra_duas < 0:
        return

    skip_trigger_lvals: set[int] = set()
    if not is_new_atp:
        prior_rows = db.session.query(Bug.trigger_lval).filter(
            Bug.atp == atp.id,
            Bug.type == bug_type.value
        ).all()
        skip_trigger_lvals = {row[0] for row in prior_rows}

    prechosen_labels: set[int] = set()
    for extra in prechosen:
        merge_into(prechosen_labels, set(extra.all_labels))

    for trigger_dua in available_duas:
        lval_id = trigger_dua.lval
        if lval_id in skip_trigger_lvals:
            continue

        selected = get_dua_dead_range(trigger_dua, list(prechosen_labels), offline_liveness, project_data)
        if selected.empty():
            continue

        trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)
        extra_duas: list[DuaBytes] = list(prechosen)
        labels_so_far: set[int] = set(prechosen_labels)
        merge_into(labels_so_far, set(trigger.all_labels))

        end_index = 0
        for i, d in enumerate(available_duas):
            if d.instr < trigger_dua.instr:
                end_index = i + 1
            else:
                break

        if num_extra_duas < end_index:
            for _ in range(num_extra_duas):
                extra = None
                tries = 0
                while tries < RANDOM_DUA_TRIES:
                    tries += 1
                    extra_dua = available_duas[random.randrange(0, end_index)]
                    extra_selected = get_dua_dead_range(
                        extra_dua, list(labels_so_far), offline_liveness, project_data
                    )
                    if extra_selected.empty():
                        continue
                    candidate = get_or_create_dua_bytes(db, dua_bytes_cache, extra_dua, extra_selected)
                    if disjoint(sorted(labels_so_far), candidate.all_labels):
                        extra = candidate
                        break
                if extra is None:
                    break
                extra_duas.append(extra)
                merge_into(labels_so_far, set(extra.all_labels))

        if len(extra_duas) < NUM_EXTRA_DUAS[bug_type]:
            continue

        if not trigger_dua.fake_dua and len(labels_so_far) < (4 * NUM_EXTRA_DUAS[bug_type]):
            continue

        c_max_liveness = get_max_liveness(offline_liveness, trigger)
        db.session.add(Bug(
            bug_type=bug_type,
            trigger=trigger,
            trigger_lval=trigger_dua.lval,
            max_liveness=c_max_liveness,
            atp=atp,
            extra_duas=[e.id for e in extra_duas],
            stackoff=stackoff
        ))


def _record_injectable_bugs_offline_lava1(project_data: dict):
    with LavaDatabase(project_data) as db:
        distinct_files = db.session.query(AtpExecution.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache: Dict[tuple, DuaBytes] = {}
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

                for bug_type in target_bug_kinds:
                    _get_or_create_bug_like_cpp(
                        db=db,
                        dua_bytes_cache=dua_bytes_cache,
                        atp=atp,
                        bug_type=bug_type,
                        stackoff=getattr(atp, 'stack_offset', 0),
                        available_duas=available_duas,
                        offline_liveness=offline_liveness,
                        project_data=project_data,
                        is_new_atp=exec_event.id == atp.id,
                        extra_duas_prechosen=[]
                    )

        db.session.commit()


def _record_injectable_bugs_offline_lava2(project_data: dict):
    """
    Experimental LAVA 2.0 bug generation path.

    Design goals:
    1. Preserve hard viability constraints from LAVA 1.0/C++ parity logic
       (dead-range selection, disjoint extra-dua label selection, cardinality gates),
       while relaxing the strict "DUA and ATP must come from same inputfile" assumption.
    2. Use execution-backed evidence to avoid purely speculative cross-file pairing.
    3. Prefer robust candidates by scoring for temporal spread (ATP instr - DUA instr)
       only after viability conditions are met.

    Reachability model for cross-file pairing:
    - ATPs remain code-location properties and are selected from observed executions.
    - DUAs are runtime-observed entities; therefore, we only pair ATP/DUA candidates when
      we have a runtime bridge through labels observed alive/dead at that ATP execution.
    - For each ATP execution event, we gather `LivenessSnapshot` for that inputfile+instr.
      A candidate DUA is considered reachable only if at least one label from that DUA
      appears in the ATP execution liveness map (or the DUA is fake_dua, which mirrors
      legacy tolerance for synthetic/chaff-compatible triggers).

    Candidate selection and ranking:
    - Build candidate DUAs from all files with instr <= ATP instr and alive at ATP point
      by death_instr semantics.
    - Keep one most-recent DUA per lval (same overwrite semantics used in lava1).
    - Filter by reachability rule above.
    - Sort primarily by maximum temporal distance first (larger ATP-DUA instr),
      then by older instr and stable id for deterministic output.
    - Feed top-ranked DUAs into the same C++-style bug materialization helper.
    """
    with LavaDatabase(project_data) as db:
        executions = db.session.query(AtpExecution).order_by(
            AtpExecution.inputfile.asc(), AtpExecution.instr.asc(), AtpExecution.id.asc()
        ).all()

        if not executions:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache: Dict[tuple, DuaBytes] = {}

        for exec_event in executions:
            atp = db.session.query(AttackPoint).get(exec_event.atp_id)
            if not atp:
                continue

            liveness_records = db.session.query(LivenessSnapshot).filter(
                LivenessSnapshot.inputfile == exec_event.inputfile,
                LivenessSnapshot.atp_instr == exec_event.instr
            ).all()
            offline_liveness: dict[int, int] = {r.label: r.liveness_count for r in liveness_records}

            target_bug_kinds = get_bug_kinds_for_atp(AtpKind(atp.type))
            if not target_bug_kinds:
                continue

            raw_duas = db.session.query(Dua).filter(
                Dua.instr <= exec_event.instr,
                (Dua.death_instr.is_(None) | (Dua.death_instr > exec_event.instr))
            ).order_by(Dua.instr.asc(), Dua.id.asc()).all()
            if not raw_duas:
                continue

            recent_duas_map: dict[int, Dua] = {}
            for d in raw_duas:
                recent_duas_map[d.lval] = d

            reachable_duas: list[Dua] = []
            for d in recent_duas_map.values():
                if d.fake_dua:
                    reachable_duas.append(d)
                    continue
                dua_labels = set(d.all_labels or [])
                if dua_labels.intersection(offline_liveness.keys()):
                    reachable_duas.append(d)

            if not reachable_duas:
                continue

            reachable_duas.sort(
                key=lambda d: (-(exec_event.instr - d.instr), d.instr, d.id)
            )

            for bug_type in target_bug_kinds:
                _get_or_create_bug_like_cpp(
                    db=db,
                    dua_bytes_cache=dua_bytes_cache,
                    atp=atp,
                    bug_type=bug_type,
                    stackoff=getattr(atp, 'stack_offset', 0),
                    available_duas=reachable_duas,
                    offline_liveness=offline_liveness,
                    project_data=project_data,
                    is_new_atp=exec_event.id == atp.id,
                    extra_duas_prechosen=[]
                )

        db.session.commit()


def record_injectable_bugs_offline(project_data: dict, mode: str = "lava1"):
    if mode == "lava1":
        _record_injectable_bugs_offline_lava1(project_data)
        return
    if mode == "lava2":
        _record_injectable_bugs_offline_lava2(project_data)
        return
    raise ValueError(f"Unknown bug-generation mode '{mode}'. Expected 'lava1' or 'lava2'.")


def print_phase2_stats(project_data: dict, debug: bool = False):
    """
    Dumps the entities specifically created/managed around Phase II.
    We skip DuaBytes as this is a noisy table and when comparing with C++
    as long as the Bugs match, the DuaBytes are not relevant to the comparison.
    """
    with LavaDatabase(project_data) as db:
        # Sort deterministically by semantic bug identity fields.
        bugs = db.session.query(Bug).order_by(
            Bug.type,
            Bug.atp,
            Bug.trigger_lval,
            Bug.extra_duas,
            Bug.max_liveness,
            Bug.stackoff,
            Bug.id
        ).all()

        if debug:
            dump_table("BUGS", bugs, ['type', 'atp', 'trigger_lval', 'extra_duas', 'max_liveness', 'stackoff'])
        else:
            print("bugs:", len(bugs))

        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))
        print("total bug:", db.session.query(Bug).count())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate code coverage using LLVM-COV.")
    parser.add_argument("--project", "-p", required=True, dest="project_name", help="Provide the LAVA project name")
    parser.add_argument("--mode", "-m", required=False, dest="mode", default="lava1", help="Specify the bug-generation mode")
    args = parser.parse_args()

    # host.json reads overall config from host.json
    # project_name finds configs for specific project
    project = parse_vars(args.project_name)
    record_injectable_bugs_offline(project, args.mode)
    print_phase2_stats(project)
