import logging
import random

from angr.exploration_techniques import ExplorationTechnique

l = logging.getLogger('KLEERandomSearch')


class KLEERandomSearch(ExplorationTechnique):
    """
    Random path selection. https://hci.stanford.edu/cstr/reports/2008-03.pdf

    Maintains a binary tree recording the program path followed for all active processes,
    i.e. the leaves of the tree are the current processes and the internal nodes are places
    where execution forked. Processes are selected by traversing this tree from the root
    and randomly selecting the path to follow at branch points. Therefore when a branch point
    is reached the set of processes in each subtree will have equal probability of being selected,
    regardless of their size.

    This is implemented as a Non-Uniform-Random-Search where child nodes inherit parent weight, divided by the number
    of siblings
    """

    def __init__(self, **kwargs):
        super(KLEERandomSearch, self).__init__()
    
    @staticmethod
    def rank(s, reverse=False):
        k = -1 if reverse else 1
        return k * s.globals['weight']
        
    def step(self, simgr, stash='active', **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        print(simgr.active)

        # if there's no branch just go on
        if len(simgr.stashes[stash]) == 1:
            return simgr

        # if we there are no successors randomly pick a new path
        elif len(simgr.stashes[stash]) == 0:
            pass  # weighted choice code is always executed before returning

        # if there is more than one successor update the binary tree and randomly pick a new path
        elif len(simgr.stashes[stash]) > 1:
            l.debug(f'{"-" * 0x10}\nStatus:\t\t{simgr} --> active: {simgr.stashes[stash]}')
            # update binary tree
            for s in simgr.stashes[stash]:
                s.globals['weight'] = s.globals.get('weight', 1) / len(simgr.stashes[stash])
            pass  # weighted choice code is always executed before returning

        # randomly pick new path
        simgr.move(from_stash=stash, to_stash='deferred')
        if max([s.globals['weight'] for s in simgr.stashes['deferred']]) < 0.1:
            for s in simgr.stashes['deferred']:
                s.globals['weight'] *= 10
        n = random.uniform(0, sum([s.globals['weight'] for s in simgr.stashes['deferred']]))
        for s in simgr.stashes['deferred']:
            if n < s.globals['weight']:
                simgr.stashes['deferred'].remove(s)
                simgr.stashes[stash] = [s]
                break
            n = n - s.globals['weight']

        return simgr