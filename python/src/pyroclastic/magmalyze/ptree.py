"""
The process tree behind KLEE's random-path selection (Cadar et al., OSDI'08, §3.4).

Leaves are live states. Internal nodes are points where execution forked. KLEE picks a
state by walking from the root and choosing a child uniformly at random at every node, so
both sides of a fork are equally likely no matter how many states each side holds. Dead
subtrees are pruned, which hands their share to the surviving siblings.

This module is plain Python (no angr), so the selection logic can be unit tested on
hand-built trees. A "state" here is any object; the angr exploration technique stores
SimStates in it.
"""
import random
from typing import Any, Optional


class PTreeNode:
    __slots__ = ("parent", "children", "state", "path", "created")

    def __init__(self, parent: Optional["PTreeNode"], path: tuple, state: Any = None, created: int = 0):
        self.parent = parent
        self.children: list["PTreeNode"] = []
        self.state = state
        # Branch labels from the root; stable even after siblings are pruned
        self.path = path
        # Creation order, used by DFS (newest leaf first)
        self.created = created

    @property
    def is_leaf(self) -> bool:
        return not self.children

    def __repr__(self):
        return f"PTreeNode(path={self.path}, leaf={self.is_leaf})"


class PTree:
    """
    A virtual root whose children are the initial states (one per seed input), so with
    several seeds each seed's subtree gets an equal share, like the rest of the tree.
    """

    def __init__(self):
        self.root = PTreeNode(None, ())
        self._counter = 0
        # Live leaves in creation order (for DFS), plus an indexable copy for uniform picks
        self._by_created: dict[int, PTreeNode] = {}
        self._leaves: list[PTreeNode] = []
        self._leaf_pos: dict[int, int] = {}

    def __len__(self) -> int:
        return len(self._leaves)

    def leaves(self) -> list[PTreeNode]:
        return list(self._leaves)

    def _new_leaf(self, parent: PTreeNode, label: int, state: Any) -> PTreeNode:
        self._counter += 1
        node = PTreeNode(parent, parent.path + (label,), state, self._counter)
        parent.children.append(node)
        self._by_created[node.created] = node
        self._leaf_pos[id(node)] = len(self._leaves)
        self._leaves.append(node)
        return node

    def _drop_leaf(self, node: PTreeNode):
        del self._by_created[node.created]
        # Swap-pop keeps removal O(1)
        pos = self._leaf_pos.pop(id(node))
        last = self._leaves.pop()
        if last is not node:
            self._leaves[pos] = last
            self._leaf_pos[id(last)] = pos

    def add_root(self, state: Any) -> PTreeNode:
        return self._new_leaf(self.root, len(self.root.children), state)

    def advance(self, leaf: PTreeNode, state: Any):
        """The leaf's state took a step without forking."""
        leaf.state = state

    def fork(self, leaf: PTreeNode, states: list, order_rng: Optional[random.Random] = None) -> list[PTreeNode]:
        """
        The leaf's state forked into len(states) >= 2 successors; it becomes an internal node.
        A k-way fork gives each child 1/k (KLEE forks two ways at a time; angr can return k>2).
        order_rng shuffles creation order only, i.e. which child DFS tries first. Labels stay
        the successors' original indices.
        """
        assert len(states) >= 2, "a fork needs at least two successors"
        self._drop_leaf(leaf)
        leaf.state = None
        labelled = list(enumerate(states))
        if order_rng is not None:
            order_rng.shuffle(labelled)
        return [self._new_leaf(leaf, label, state) for label, state in labelled]

    def kill(self, leaf: PTreeNode):
        """The leaf's state terminated. Prune it, and every ancestor left with no children."""
        self._drop_leaf(leaf)
        leaf.state = None
        node = leaf
        while node.parent is not None and node.is_leaf:
            node.parent.children.remove(node)
            node = node.parent

    # --- Selection strategies -------------------------------------------------------

    def select_random_path(self, rng: random.Random) -> Optional[PTreeNode]:
        """KLEE random-path: walk from the root, uniform choice at each node."""
        node = self.root
        if not node.children:
            return None
        while node.children:
            node = rng.choice(node.children)
        return node

    def select_uniform(self, rng: random.Random) -> Optional[PTreeNode]:
        """Uniform over live states. Random, but NOT KLEE: it starves the less-forked side."""
        return rng.choice(self._leaves) if self._leaves else None

    def select_dfs(self) -> Optional[PTreeNode]:
        """Depth-first: always the newest live leaf, which backtracks when a path dies."""
        if not self._by_created:
            return None
        return self._by_created[next(reversed(self._by_created))]

    def oldest_leaf(self) -> Optional[PTreeNode]:
        """The live leaf created first; what a memory cap drops."""
        if not self._by_created:
            return None
        return self._by_created[next(iter(self._by_created))]
