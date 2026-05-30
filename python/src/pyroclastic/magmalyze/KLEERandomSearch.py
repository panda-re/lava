import logging
import random
from angr.exploration_techniques import ExplorationTechnique
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_manager.py#L27
from angr.sim_manager import SimulationManager
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_state.py#L60
from angr.sim_state import SimState

logger = logging.getLogger('KLEERandomSearch')
logger.setLevel(logging.DEBUG)


class KLEERandomSearch(ExplorationTechnique):
    """
    KLEE Random Path Selection (General Purpose Version)
    Paper: https://hci.stanford.edu/cstr/reports/2008-03.pdf
    """

    def __init__(self, **kwargs):
        super(KLEERandomSearch, self).__init__()

    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        # 1. Execute the next step
        simgr : SimulationManager = simgr.step(stash=stash, **kwargs)

        # 2. Pool all states (Active + Deferred) to make a global weighted choice
        simgr.move(from_stash=stash, to_stash='deferred')

        # Adding the type hint as requested: list[SimState]
        # In Angr, the stashes are essentially lists of SimState objects.
        deferred: list[SimState] = simgr.stashes['deferred']

        if not deferred:
            return simgr

        # 3. Calculate weights
        weights: list[float] = []
        for state in deferred:
            # FIX: Using 'state.history.depth' as a fallback,
            # or specifically counting 'branch' events in the history.
            # Most robust way across angr versions to find "how many times have I branched":
            fork_count = sum(1 for ev in state.history.events if ev.type == 'branch')

            # If for some reason 'branch' events aren't being logged in your config,
            # we use state.history.depth (block count) as a fallback, though it's less 'pure' KLEE.
            if fork_count == 0 and state.history.depth > 0:
                # We'll use a scaled version of depth if no explicit branches found
                weight = 0.5 ** min(state.history.depth // 10, 1022)
            else:
                weight = 0.5 ** min(fork_count, 1022)

            weights.append(weight)

        # 4. Weighted Random Selection
        try:
            selected_state: SimState = random.choices(deferred, weights=weights, k=1)[0]
        except (ValueError, IndexError):
            selected_state: SimState = random.choice(deferred)

        # 5. Restore the chosen state to active
        simgr.stashes['deferred'].remove(selected_state)
        simgr.stashes[stash] = [selected_state]

        # Detailed logging for your debugging
        logger.debug(f"KLEE Select: Pool={len(deferred)} | Chosen Depth={selected_state.history.depth}")

        return simgr

    def setup(self, simgr: SimulationManager):
        if 'deferred' not in simgr.stashes:
            simgr.stashes['deferred'] = []