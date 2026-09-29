"""
The selection logic of KLEE random-path, on hand-built trees.
Pure Python, no angr, well under a second. Probabilities are checked against their exact
values with a tolerance of ~6 binomial standard errors, from a fixed seed.
"""
import math
import random
import unittest

from pyroclastic.magmalyze.ptree import PTree

DRAWS = 20000


def build_balanced(depth: int) -> tuple[PTree, list]:
    """A full binary tree of the given depth under one root; returns the tree and its leaves."""
    tree = PTree()
    frontier = [tree.add_root("root")]
    for _ in range(depth):
        nxt = []
        for leaf in frontier:
            nxt.extend(tree.fork(leaf, ["a", "b"]))
        frontier = nxt
    return tree, frontier


def build_lopsided(deep_depth: int) -> tuple[PTree, object, list]:
    """root -> {shallow leaf S, subtree of 2**deep_depth leaves}."""
    tree = PTree()
    root = tree.add_root("root")
    shallow, deep = tree.fork(root, ["S", "deep"])
    frontier = [deep]
    for _ in range(deep_depth):
        nxt = []
        for leaf in frontier:
            nxt.extend(tree.fork(leaf, ["a", "b"]))
        frontier = nxt
    return tree, shallow, frontier


def share(picks: list, node) -> float:
    return sum(1 for p in picks if p is node) / len(picks)


def band(p: float, n: int = DRAWS, sigmas: float = 6.0) -> float:
    return sigmas * math.sqrt(p * (1 - p) / n)


class RandomPathSelection(unittest.TestCase):

    def test_balanced_tree_is_uniform_over_leaves(self):
        tree, leaves = build_balanced(8)
        rng = random.Random(1)
        counts = {id(leaf): 0 for leaf in leaves}
        for _ in range(DRAWS):
            counts[id(tree.select_random_path(rng))] += 1
        # Chi-square goodness of fit against 1/256 each (df = 255). The critical value for
        # p = 1e-6 is about 388; a biased selector is far past it.
        expected = DRAWS / len(leaves)
        chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
        self.assertLess(chi2, 388, f"chi-square {chi2:.1f} says leaves aren't uniform")

    def test_lopsided_tree_gives_each_side_half(self):
        """The defining KLEE property: the shallow leaf gets 1/2 against 255 deep leaves."""
        tree, shallow, _ = build_lopsided(8)
        rng = random.Random(2)
        picks = [tree.select_random_path(rng) for _ in range(DRAWS)]
        self.assertAlmostEqual(share(picks, shallow), 0.5, delta=band(0.5))

    def test_uniform_baseline_starves_the_shallow_side(self):
        """Uniform state selection is random too, but gives the shallow leaf only 1/257."""
        tree, shallow, _ = build_lopsided(8)
        rng = random.Random(3)
        picks = [tree.select_uniform(rng) for _ in range(DRAWS)]
        p = 1 / 257
        self.assertAlmostEqual(share(picks, shallow), p, delta=band(p))

    def test_dead_subtree_hands_its_share_to_the_sibling(self):
        """
        Kill 3 of the 4 grandchildren of one side: random-path gives the lone survivor that
        whole side's 1/2. Weighting each leaf by 2**-depth would give it 1/4 / (1/4+1/2) = 1/3.
        """
        tree = PTree()
        root = tree.add_root("root")
        left, right = tree.fork(root, ["l", "r"])
        survivor, *doomed = [c for leaf in tree.fork(left, ["a", "b"]) for c in tree.fork(leaf, ["x", "y"])]
        for leaf in doomed:
            tree.kill(leaf)
        rng = random.Random(4)
        picks = [tree.select_random_path(rng) for _ in range(DRAWS)]
        self.assertAlmostEqual(share(picks, survivor), 0.5, delta=band(0.5))
        self.assertAlmostEqual(share(picks, right), 0.5, delta=band(0.5))

    def test_three_way_fork_is_a_third_each(self):
        tree = PTree()
        children = tree.fork(tree.add_root("root"), ["a", "b", "c"])
        rng = random.Random(5)
        picks = [tree.select_random_path(rng) for _ in range(DRAWS)]
        for child in children:
            self.assertAlmostEqual(share(picks, child), 1 / 3, delta=band(1 / 3))

    def test_each_seed_gets_an_equal_share(self):
        """Several initial states (one per seed input) each get 1/k, whatever their size."""
        tree = PTree()
        small = tree.add_root("seed0")
        big = tree.add_root("seed1")
        frontier = [big]
        for _ in range(6):
            frontier = [c for leaf in frontier for c in tree.fork(leaf, ["a", "b"])]
        rng = random.Random(6)
        picks = [tree.select_random_path(rng) for _ in range(DRAWS)]
        self.assertAlmostEqual(share(picks, small), 0.5, delta=band(0.5))

    def test_same_seed_same_sequence(self):
        tree, _ = build_balanced(6)
        rng1, rng2 = random.Random(8), random.Random(8)
        seq1 = [tree.select_random_path(rng1).path for _ in range(200)]
        seq2 = [tree.select_random_path(rng2).path for _ in range(200)]
        self.assertEqual(seq1, seq2)


class TreeBookkeeping(unittest.TestCase):

    def test_pruning_removes_empty_ancestors(self):
        tree = PTree()
        root = tree.add_root("root")
        a, b = tree.fork(root, ["a", "b"])
        a1, a2 = tree.fork(a, ["x", "y"])
        for leaf in (a1, a2):
            tree.kill(leaf)
        # The whole "a" subtree is gone, so b is the only thing left under the seed
        self.assertEqual(len(tree), 1)
        self.assertEqual(root.children, [b])
        tree.kill(b)
        self.assertEqual(len(tree), 0)
        self.assertEqual(tree.root.children, [])
        self.assertIsNone(tree.select_random_path(random.Random(0)))
        self.assertIsNone(tree.select_uniform(random.Random(0)))
        self.assertIsNone(tree.select_dfs())

    def test_paths_are_stable_labels(self):
        tree = PTree()
        root = tree.add_root("root")
        a, b = tree.fork(root, ["a", "b"])
        tree.kill(a)
        # b keeps its label 1 even though it's now its parent's only child
        self.assertEqual(b.path, (0, 1))
        c = tree.fork(b, ["x", "y"])[1]
        self.assertEqual(c.path, (0, 1, 1))

    def test_advance_keeps_the_leaf(self):
        tree = PTree()
        leaf = tree.add_root("s0")
        tree.advance(leaf, "s1")
        self.assertEqual(leaf.state, "s1")
        self.assertEqual(len(tree), 1)

    def test_dfs_finishes_a_subtree_before_leaving_it(self):
        """DFS is always the newest leaf, so it drains one side of a fork before the other."""
        tree = PTree()
        order_rng = random.Random(9)
        tree.add_root("root")
        visited = []
        while len(tree):
            leaf = tree.select_dfs()
            if len(leaf.path) < 4:
                tree.fork(leaf, ["a", "b"], order_rng=order_rng)
            else:
                visited.append(leaf.path)
                tree.kill(leaf)
        self.assertEqual(len(visited), 8)
        # The first-decision label changes exactly once across the visit order
        firsts = [p[1] for p in visited]
        changes = sum(1 for x, y in zip(firsts, firsts[1:]) if x != y)
        self.assertEqual(changes, 1)


if __name__ == '__main__':
    unittest.main()
