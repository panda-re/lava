import logging
from typing import cast, Dict
import argparse
from sqlalchemy.orm import joinedload
from ..utils.database_types import AttackPoint, Bug, \
    DuaBytes, Dua, LavaDatabase, BugKind, AtpExecution, AtpKind, LivenessSnapshot, Range
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


def most_recent_dua_per_lval(duas: list[Dua]) -> dict[int, Dua]:
    """
    Collapse a DUA list down to one entry per source lval, keeping whichever DUA has
    the highest instr (i.e. the most recently (re-)discovered incarnation of that
    lval). `duas` is expected pre-sorted by instr ascending (Dua.instr.asc()), so a
    later entry for the same lval always overwrites an earlier one -- this is the
    exact "lval reuse" overwrite semantics both find_bug_inj.cpp's recent_dead_duas
    map and _record_injectable_bugs_offline_lava1's reconstruction of it rely on.
    Shared so any offline bug-generation pass (lava1, lava2, future algorithms) that
    needs "what DUAs are alive at this instant" gets the same answer.
    """
    by_lval: dict[int, Dua] = {}
    for d in duas:
        by_lval[d.lval] = d
    return by_lval


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
        merge_into(prechosen_labels, set[int](extra.all_labels))

    for trigger_dua in available_duas:
        lval_id = trigger_dua.lval
        if lval_id in skip_trigger_lvals:
            continue

        # disjoint() merges two ascending-sorted sequences -- a raw list(some_set)
        # is NOT guaranteed sorted (Python set iteration order depends on the hash
        # table's internal layout, not insertion order), so an unsorted to_avoid
        # here silently breaks the merge and can wrongly accept/reject bytes.
        selected = get_dua_dead_range(trigger_dua, sorted(prechosen_labels), offline_liveness, project_data)
        if selected.empty():
            continue

        trigger = get_or_create_dua_bytes(db, dua_bytes_cache, trigger_dua, selected)
        extra_duas: list[DuaBytes] = list[DuaBytes](prechosen)
        labels_so_far: set[int] = set[int](prechosen_labels)
        merge_into(labels_so_far, set[int](trigger.all_labels))

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
                    # Deterministic parity mode: avoid RNG differences (Python vs C++).
                    # We intentionally pick the first prior DUA every try to keep outputs
                    # diff-stable against C++ bug mining logs. Randomized selection can be
                    # reintroduced later once parity checks are complete.
                    extra_dua = available_duas[0]
                    # same requirement as above: to_avoid must be sorted ascending.
                    extra_selected = get_dua_dead_range(
                        extra_dua, sorted(labels_so_far), offline_liveness, project_data
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
                merge_into(labels_so_far, set[int](extra.all_labels))

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
        distinct_files = db.session.query(Dua.inputfile).distinct().all()
        file_list = [f[0] for f in distinct_files]

        if not file_list:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache: Dict[tuple, DuaBytes] = {}
        for inputfile in file_list:
            print(f"[*] Processing bug combinatorics target file: {inputfile}...")
            executions = db.session.query(AtpExecution).filter_by(inputfile=inputfile).order_by(
                AtpExecution.instr.asc(), AtpExecution.id.asc()).all()
            dua_stream = db.session.query(Dua).filter_by(inputfile=inputfile).order_by(
                Dua.instr.asc(), Dua.id.asc()).all()

            if not executions:
                continue

            executions_by_instr: dict[int, list[AtpExecution]] = {}
            for ex in executions:
                executions_by_instr.setdefault(ex.instr, []).append(ex)

            # C++ locates the RET_BUFFER pad's AttackPoint by (loc, type) alone, which
            # is the exact same row used for the QUERY_POINT AttackPoint at that source
            # location -- build that lookup once instead of re-querying per dua.
            query_point_atp_by_loc: dict = {}
            for ex in executions:
                candidate = db.session.query(AttackPoint).get(ex.atp_id)
                if candidate is not None and AtpKind(candidate.type) == AtpKind.QUERY_POINT:
                    query_point_atp_by_loc[candidate.loc] = candidate

            recent_dead_duas: dict[int, Dua] = {}
            recent_duas_by_instr: list[Dua] = []
            dua_idx = 0

            def prune_recent_duas(current_instr: int):
                expired = [
                    lval_id for lval_id, d in recent_dead_duas.items()
                    if d.death_instr is not None and d.death_instr <= current_instr
                ]
                for lval_id in expired:
                    d = recent_dead_duas.pop(lval_id, None)
                    if d is not None:
                        try:
                            recent_duas_by_instr.remove(d)
                        except ValueError:
                            pass

            ordered_instrs = sorted(executions_by_instr.keys())
            for instr in ordered_instrs:
                # Collect this checkpoint's newly-observed duas WITHOUT inserting them
                # yet. Several duas can share the exact same instr (e.g. a struct
                # scanned field-by-field in one hypercall burst), and C++ generates
                # RET_BUFFER for dua i strictly BEFORE dua i replaces whatever
                # (possibly older) dua currently occupies its own lval slot. So
                # insertion has to interleave with RET_BUFFER generation below, not
                # happen as one batch up front.
                newly_observed_duas: list[Dua] = []
                while dua_idx < len(dua_stream) and dua_stream[dua_idx].instr <= instr:
                    newly_observed_duas.append(dua_stream[dua_idx])
                    dua_idx += 1

                liveness_records = db.session.query(LivenessSnapshot).filter(
                    LivenessSnapshot.inputfile == inputfile,
                    LivenessSnapshot.atp_instr == instr
                ).all()
                offline_liveness: dict[int, int] = {r.label: r.liveness_count for r in liveness_records}

                for d in newly_observed_duas:
                    if d.length >= 20:
                        pad = get_dua_exploit_pad(d, offline_liveness)
                        if not pad.empty() and (d.fake_dua or pad.size() >= 20):
                            trigger = get_or_create_dua_bytes(db, dua_bytes_cache, d, pad)
                            d_atp = query_point_atp_by_loc.get(d.lval_relationship.loc)
                            if d_atp is not None:
                                # recent_dead_duas does NOT yet contain `d` here -- any
                                # older dua still registered at d's own lval stays a
                                # legal trigger, matching C++'s insertion order.
                                _get_or_create_bug_like_cpp(
                                    db=db,
                                    dua_bytes_cache=dua_bytes_cache,
                                    atp=d_atp,
                                    bug_type=BugKind.BUG_RET_BUFFER,
                                    stackoff=0,
                                    available_duas=sorted(recent_dead_duas.values(), key=lambda x: x.instr),
                                    offline_liveness=offline_liveness,
                                    project_data=project_data,
                                    is_new_atp=False,
                                    extra_duas_prechosen=[trigger]
                                )

                    if d.lval in recent_dead_duas:
                        old_dua = recent_dead_duas[d.lval]
                        try:
                            recent_duas_by_instr.remove(old_dua)
                        except ValueError:
                            pass
                    recent_dead_duas[d.lval] = d
                    recent_duas_by_instr.append(d)

                # Deaths recorded at this exact same instr are pruned only now, after
                # every newly-observed dua at this checkpoint has had its own shot at
                # RET_BUFFER above. PANDA's instr granularity is coarser than the true
                # pandalog event sequence, so a death and a dua discovery can share one
                # instr value with no way to tell, from instr alone, which the real log
                # ordered first; C++, replaying the log verbatim, doesn't have this
                # ambiguity. Giving new arrivals first crack at anything not yet pruned
                # is what actually recovers C++'s RET_BUFFER count on this trace (verified
                # against a from-scratch, non-batched replay of queries-toy.json).
                prune_recent_duas(instr)

                if not recent_dead_duas:
                    continue

                for exec_event in executions_by_instr[instr]:
                    atp = db.session.query(AttackPoint).get(exec_event.atp_id)
                    if not atp:
                        continue

                    target_bug_kinds: list[BugKind] = get_bug_kinds_for_atp(AtpKind(atp.type))
                    if not target_bug_kinds:
                        continue

                    available_duas = sorted(recent_dead_duas.values(), key=lambda x: x.instr)
                    if not available_duas:
                        continue

                    for bug_type in target_bug_kinds:
                        if bug_type in (
                            BugKind.BUG_RET_BUFFER,
                            BugKind.BUG_CHAFF_STACK_UNUSED,
                            BugKind.BUG_CHAFF_STACK_CONST,
                            BugKind.BUG_CHAFF_HEAP_CONST,
                            BugKind.BUG_CHAFF_DIVZERO
                        ):
                            continue
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

                    if AtpKind(atp.type) == AtpKind.QUERY_POINT:
                        _get_or_create_bug_like_cpp(
                            db=db,
                            dua_bytes_cache=dua_bytes_cache,
                            atp=atp,
                            bug_type=BugKind.BUG_CHAFF_STACK_UNUSED,
                            stackoff=getattr(atp, 'stack_offset', 0),
                            available_duas=available_duas,
                            offline_liveness=offline_liveness,
                            project_data=project_data,
                            is_new_atp=False,
                            extra_duas_prechosen=[]
                        )

                        if recent_duas_by_instr:
                            exploit_dua = recent_duas_by_instr[0]
                            exploit_range = get_dua_dead_range(exploit_dua, [], offline_liveness, project_data)
                            if not exploit_range.empty():
                                exploit_db = get_or_create_dua_bytes(db, dua_bytes_cache, exploit_dua, exploit_range)
                                for chaff_kind in (
                                    BugKind.BUG_CHAFF_STACK_CONST,
                                    BugKind.BUG_CHAFF_HEAP_CONST,
                                    BugKind.BUG_CHAFF_DIVZERO,
                                ):
                                    _get_or_create_bug_like_cpp(
                                        db=db,
                                        dua_bytes_cache=dua_bytes_cache,
                                        atp=atp,
                                        bug_type=chaff_kind,
                                        stackoff=getattr(atp, 'stack_offset', 0),
                                        available_duas=available_duas,
                                        offline_liveness=offline_liveness,
                                        project_data=project_data,
                                        is_new_atp=False,
                                        extra_duas_prechosen=[exploit_db]
                                    )

        db.session.commit()


def _record_injectable_bugs_offline_lava2(project_data: dict):
    """
    Experimental LAVA 2.0 bug generation path: same attack-point-triggered bug types
    LAVA 1.0 finds (PTR_ADD, REL_WRITE, PRINTF_LEAK, MALLOC_OFF_BY_ONE), but instead of
    only ever considering the ONE input file that happened to record a given attack
    point, it pools every file's recording of that SAME source-code attack point and
    picks whichever occurrence puts the most instructions between the DUA being read
    and the ATP consuming it. A bigger DUA<->ATP instruction distance means more
    intervening dataflow/control-flow for a fuzzer to have to reconstruct by accident,
    which is the whole point of the exercise (A/B'ing against LAVA 1.0 in FuzzBench).

    Why this ISN'T "combine a DUA from file A with an ATP from file B":
    lavaTool's actual bug-injection mechanism (the `lava_val[]` global siphon array,
    see tools/lavaTool) has no per-file restriction at all -- a DUA siphoned in one
    source file and an ATP drained in another link fine. The real constraint is
    downstream, in inject.py's validation step: it mutates a SINGLE chosen input file,
    poking the trigger's and every extra DUA's byte offsets into that one file
    (`mutate_file`). So every DUA used by one Bug (trigger + extra_duas) MUST come from
    the same inputfile, or there is no single file left that can actually solve it --
    this is the exact "difficult/impossible to generate solutions" trap. This function
    keeps that bond intact: candidates for a given (inputfile, instr) execution are
    drawn only from that same inputfile, so trigger and extras always agree.

    What actually changes from LAVA 1.0's is the SEARCH SPACE, not the SOLVABILITY
    contract: instead of walking one file's timeline and taking the closest surviving
    DUA at each attack-point visit, we look at that same attack point across every
    file that ever executed it, and only keep the single farthest-apart occurrence of
    each (attack point, bug type, trigger lval) triple -- see the ordering comment
    below for how that's achieved with no extra bookkeeping.

    Not (yet) covered here: RET_BUFFER and the CHAFF_* types. Those need lava1's
    incremental exploit-pad selection (get_dua_exploit_pad / "oldest still-alive DUA in
    this file's timeline"), which is inherently a walk over ONE file's continuous
    DUA/liveness history; there's no well-defined cross-execution analogue of "the
    pad" yet, so mixing that machinery in here would just produce weaker versions of
    what lava1 already does correctly. AtpKind.QUERY_POINT attack points (the only ones
    that map to those bug types) are skipped entirely.
    """
    with LavaDatabase(project_data) as db:
        executions = db.session.query(AtpExecution).order_by(
            AtpExecution.atp_id.asc(), AtpExecution.inputfile.asc(), AtpExecution.instr.asc()
        ).all()

        if not executions:
            print("[-] No Attack Points were executed. Skipping bug generation.")
            return

        dua_bytes_cache: Dict[tuple, DuaBytes] = {}

        executions_by_atp: dict[int, list[AtpExecution]] = {}
        for ex in executions:
            executions_by_atp.setdefault(ex.atp_id, []).append(ex)

        for atp_id, atp_executions in executions_by_atp.items():
            atp = db.session.query(AttackPoint).get(atp_id)
            if not atp:
                continue

            target_bug_kinds = [
                bt for bt in get_bug_kinds_for_atp(AtpKind(atp.type))
                if bt not in (
                    BugKind.BUG_RET_BUFFER,
                    BugKind.BUG_CHAFF_STACK_UNUSED,
                    BugKind.BUG_CHAFF_STACK_CONST,
                    BugKind.BUG_CHAFF_HEAP_CONST,
                    BugKind.BUG_CHAFF_DIVZERO,
                )
            ]
            if not target_bug_kinds:
                continue

            # One candidate group per (inputfile, instr) this attack point was
            # actually observed executing at, restricted to DUAs from that SAME
            # inputfile (the solvability contract explained above). Extra DUAs for
            # multi-dua bug types (REL_WRITE) still get selected from the full group,
            # not a single candidate, so that selection logic keeps working unchanged.
            groups: dict[tuple, list[Dua]] = {}
            for ex in atp_executions:
                raw_duas = db.session.query(Dua).filter(
                    Dua.inputfile == ex.inputfile,
                    Dua.instr <= ex.instr,
                    (Dua.death_instr.is_(None) | (Dua.death_instr > ex.instr))
                ).order_by(Dua.instr.asc(), Dua.id.asc()).all()
                if not raw_duas:
                    continue
                alive = most_recent_dua_per_lval(raw_duas)
                groups[(ex.inputfile, ex.instr)] = sorted(alive.values(), key=lambda d: d.instr)

            if not groups:
                continue

            # Visit groups with the largest possible DUA<->ATP distance first. A
            # Bug's (atp, type, trigger_lval) identity is globally unique -- see the
            # skip-list check at the top of _get_or_create_bug_like_cpp's trigger
            # loop -- so once the farthest occurrence of a given trigger lval claims
            # that identity, every closer occurrence of the SAME lval encountered
            # afterwards is automatically skipped. Ordering groups this way is all it
            # takes to make "maximize distance" a real selection criterion instead of
            # a no-op sort over a list every entry of which gets used anyway.
            def group_max_distance(key: tuple) -> int:
                instr = key[1]
                oldest_alive = groups[key][0]  # sorted ascending by instr above
                return instr - oldest_alive.instr

            ordered_keys = sorted(groups.keys(), key=group_max_distance, reverse=True)

            for inputfile, instr in ordered_keys:
                liveness_records = db.session.query(LivenessSnapshot).filter(
                    LivenessSnapshot.inputfile == inputfile,
                    LivenessSnapshot.atp_instr == instr
                ).all()
                offline_liveness: dict[int, int] = {r.label: r.liveness_count for r in liveness_records}
                available_duas = groups[(inputfile, instr)]

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
                        is_new_atp=False,
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


def _bug_atp_key(bug: Bug) -> tuple:
    """Resolve a Bug's atp to its real-world identity (source loc + type) instead
    of the raw auto-increment id. IDs only happen to line up between a C++ run and
    a Python run because both populate a freshly-wiped DB in the same order --
    that's not guaranteed on a bigger/more-branching project, where an id-based
    diff would flag two runs' identical bugs as mismatched just because they were
    discovered in a different order."""
    atp = bug.atp_relationship
    loc = atp.loc
    return (loc.filename, loc.begin.line, loc.begin.column, loc.end.line, loc.end.column, atp.type)


def _bug_lval_key(bug: Bug) -> tuple:
    """Same idea as _bug_atp_key, for the trigger's source lval (loc + ast_name)."""
    lval = bug.lval_relationship
    loc = lval.loc
    return (loc.filename, loc.begin.line, loc.begin.column, loc.end.line, loc.end.column, lval.ast_name)


def _dump_bugs(bugs: list[Bug]):
    print(f"\n==================================================")
    print(f"=== BUGS (Row Count: {len(bugs)}) ===")
    print(f"==================================================")
    for idx, bug in enumerate(bugs):
        a = _bug_atp_key(bug)
        t = _bug_lval_key(bug)
        atp_str = f"{a[0]}:{a[1]}:{a[2]}:{a[3]}:{a[4]} [{AtpKind(a[5]).name}]"
        trig_str = f"{t[0]}:{t[1]}:{t[2]}:{t[3]}:{t[4]} {t[5]}"
        print(f"  [{idx}] Row Instance Entry:")
        print(f"    - {'type':<16}: {BugKind(bug.type).name:<55} | Type: BugKind")
        print(f"    - {'atp':<16}: {atp_str:<55} | Type: AttackPoint")
        print(f"    - {'trigger_lval':<16}: {trig_str:<55} | Type: SourceLval")
        print(f"    - {'max_liveness':<16}: {str(bug.max_liveness):<55} | Type: int")
        print(f"    - {'stackoff':<16}: {str(bug.stackoff):<55} | Type: int")
        # Not the extra_duas ids themselves (same fickleness as DuaBytes -- those
        # ids depend on insertion order too), just the count, which should always
        # equal NUM_EXTRA_DUAS[bug.type] and is otherwise invisible in this dump.
        print(f"    - {'num_extra_duas':<16}: {str(len(bug.extra_duas)):<55} | Type: int")


def print_phase2_stats(project_data: dict, debug: bool = False):
    """
    Dumps the entities specifically created/managed around Phase II.
    We skip DuaBytes as this is a noisy table and when comparing with C++
    as long as the Bugs match, the DuaBytes are not relevant to the comparison.
    """
    with LavaDatabase(project_data) as db:
        if debug:
            bugs = db.session.query(Bug).options(
                joinedload(Bug.atp_relationship),
                joinedload(Bug.lval_relationship),
            ).all()
            # Sort by resolved semantic identity (see _bug_atp_key/_bug_lval_key),
            # not raw ids, so the printed order -- and any diff against it -- is
            # stable across separately-populated databases.
            bugs.sort(key=lambda b: (b.type, _bug_atp_key(b), _bug_lval_key(b), b.max_liveness, b.stackoff))
            _dump_bugs(bugs)
        else:
            print("bugs:", db.session.query(Bug).count())

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
