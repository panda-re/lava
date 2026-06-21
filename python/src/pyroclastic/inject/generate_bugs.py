from sqlalchemy import select
from bisect import bisect_left
from sqlalchemy.orm import Session
from ..utils.database_types import AttackPoint, Bug, \
    ASTLoc, DuaBytes, SourceLval, LabelSet, Dua, Range, LavaDatabase, AtpKind, BugKind

def record_injectable_bugs_at(bug_type: BugKind, atp: AttackPoint, is_new_atp: bool,
                              session: Session, extra_duas_prechosen: list[DuaBytes], project_data: dict):
    """
    Record injectable bugs at a given attack point (atp) of a given type (bug_type).
    """
    skip_trigger_lval_ids = []

    # --- 1. THE ODB REPLACEMENT ---
    if not is_new_atp:
        # In C++, this query was cached. In Python/Postgres, just run it.
        # We want to find all 'trigger_lval_id's that successfully generated
        # a bug for this specific ATP and BUG TYPE.
        stmt = select(Bug.trigger_lval).where(
            Bug.atp == atp.id,
            Bug.type == bug_type
        )
        # scalars() extracts the single value from the row automatically
        # This returns a clean List[int] that the IDE understands perfectly
        skip_trigger_lval_ids = sorted(session.scalars(stmt).all())

    skip_it = 0

    # --- 2. Fix Bug Metadata Access ---
    # Use the dictionary we defined in the Bug class
    required_extra = Bug.required_extra_duas_for_type[bug_type]
    num_extra_duas = required_extra - len(extra_duas_prechosen)
    assert num_extra_duas >= 0

    prechosen_labels : list[int] = []
    for extra in extra_duas_prechosen:
        merge_into(extra.all_labels, prechosen_labels)

    # Loop over recent_dead_duas (Dict: lval_id -> Dua object)
    for lval_id, trigger_dua in recent_dead_duas.items():

        # --- 3. The Skip Logic (Linear Scan on Sorted Lists) ---
        # Fast-forward skip_it so it matches or exceeds current lval_id
        while skip_it < len(skip_trigger_lval_ids) and skip_trigger_lval_ids[skip_it] < lval_id:
            skip_it += 1

        # If we found a match, this LVAL + ATP + TYPE combo has been done. Skip.
        if skip_it < len(skip_trigger_lval_ids) and skip_trigger_lval_ids[skip_it] == lval_id:
            continue

        # --- 4. Range Logic ---
        selected : Range = get_dua_dead_range(trigger_dua, prechosen_labels, project_data)
        # Ensure LAVA_MAGIC_VALUE_SIZE is defined/imported
        if selected.empty() or selected.size() < LAVA_MAGIC_VALUE_SIZE:
            continue

        # --- 5. Fix get_or_create for DuaBytes ---
        # Assuming DuaBytes takes 'dua' and 'selected_range' columns
        trigger_duabytes, _ = get_or_create(
            session,
            DuaBytes,
            dua=trigger_dua.id,
            selected=selected
        )

        extra_duas = list(extra_duas_prechosen)
        labels_so_far = list(prechosen_labels)
        merge_into(trigger_duabytes.all_labels, labels_so_far)

        # --- 6. Fix "lower_bound" (Performance) ---
        # C++ std::lower_bound is Binary Search.
        # Python 'next(...)' is Linear Search (Slow!).
        # We use bisect_left on 'recent_duas_by_instr'.
        # Since recent_duas_by_instr contains objects, we need a key.
        # Python 3.10+ supports key in bisect.

        # Find index where dua.instr >= trigger_dua.instr
        end_idx = bisect_left(
            recent_duas_by_instr,
            trigger_dua.instr,
            key=lambda d: d.instr
        )

        begin_idx = 0
        distance = end_idx - begin_idx

        if num_extra_duas < distance:
            for _ in range(num_extra_duas):
                extra = None
                for tries in range(2):
                    # Random index in range
                    idx = random.randint(begin_idx, end_idx - 1)
                    extra_dua = recent_duas_by_instr[idx]

                    selected_extra : Range = get_dua_dead_range(extra_dua, labels_so_far, project_data)
                    if selected_extra.empty():
                        continue

                    extra, _ = get_or_create(
                        session,
                        DuaBytes,
                        dua=extra_dua.id,
                        selected=selected_extra
                    )

                    if disjoint(labels_so_far, extra.all_labels):
                        break

                if extra is None:
                    break  # Failed to find a disjoint extra dua

                extra_duas.append(extra)
                # merge_into modifies labels_so_far in place
                merge_into(extra.all_labels, labels_so_far)

        if len(extra_duas) < required_extra:
            continue

        if not trigger_duabytes.dua_relationship.fake_dua:
            if not (len(labels_so_far) >= 4 * required_extra):
                continue

        # Calculate max liveness
        c_max_liveness = 0
        for l in trigger_duabytes.all_labels:
            c_max_liveness = max(c_max_liveness, liveness[l])

        # Assertions
        assert bug_type != BugKind.BUG_RET_BUFFER or atp.type == AtpKind.QUERY_POINT
        assert len(extra_duas) == required_extra

        # --- 7. Save Bug ---
        # The Bug Model expects 'extra_duas' to be a LIST OF IDs (Array[BigInt]),
        # not a list of objects. We extract .id here.
        extra_duas_ids = [d.id for d in extra_duas]

        bug = Bug(
            bug_type=bug_type,
            trigger=trigger_duabytes,
            max_liveness=c_max_liveness,
            atp=atp,
            extra_duas=extra_duas_ids
        )

        session.add(bug)  # SQLAlchemy's version of persist()


def print_bug_stats(project_data: dict):
    with LavaDatabase(project_data) as db:
        print("total bug:", db.session.query(Bug).count())
        print("Count\tBug Num\tName")
        for kind in BugKind:
            n = db.session.query(Bug).filter(Bug.type == kind).count()
            print("%d\t%d\t%s" % (n, kind.value, kind.name))


def create_bugs():
    pass


if __name__ == "__main__":
    create_bugs()
