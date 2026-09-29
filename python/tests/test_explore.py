"""
KLEE random-path in angr on two tiny targets. Needs angr and a
C compiler; skipped without either, or with LAVA_SKIP_ANGR_TESTS=1.

Every run uses a fixed seed and a step budget (not a wall-clock timeout), so results are
deterministic. Thresholds sit several standard deviations from the expected values; see the
comments. When matplotlib is installed, the same runs are also drawn to
$LAVA_TEST_REPORTS (default: test_reports/), which CI uploads as an artifact.

To look at the pictures yourself: magmalyze-demo
"""
import os
import shutil
import subprocess
import tempfile
import unittest

from pyroclastic.magmalyze import explore_demo as demo

REPORTS = os.environ.get("LAVA_TEST_REPORTS", "test_reports")
SEED = 7
# labyrinth_lopsided, measured over seeds 1-5: KLEE's shallow-side share
# was 0.48-0.51 over ~420 selections (binomial sd ~0.024, so 0.4 is ~4 sd away), and
# uniform's was 0.013-0.015
SHALLOW_SHARE_KLEE_MIN = 0.4
SHALLOW_SHARE_UNIFORM_MAX = 0.1


def _skip_reason():
    if os.environ.get("LAVA_SKIP_ANGR_TESTS"):
        return "LAVA_SKIP_ANGR_TESTS is set"
    if shutil.which("cc") is None:
        return "no C compiler (cc)"
    try:
        import angr  # noqa: F401
    except ImportError:
        return "angr is not installed"
    return None


SKIP = _skip_reason()


@unittest.skipIf(SKIP is not None, SKIP or "")
class LabyrinthExploration(unittest.TestCase):
    """Balanced tree of 256 paths: KLEE finds them all, in an order that isn't depth-first."""

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="labyrinth_")
        cls.binary = demo.build_target("labyrinth", cls.workdir)
        seed_file = demo.zero_seed("labyrinth", cls.workdir)
        # KLEE runs to exhaustion (about a minute); DFS only needs enough completions to
        # show its shape
        cls.klee = demo.run("labyrinth", cls.binary, seed_file, "klee", SEED)
        cls.dfs = demo.run("labyrinth", cls.binary, seed_file, "dfs", SEED, max_steps=2000)
        cls.klee_paths = demo.lr_paths(cls.klee)
        cls.dfs_paths = demo.lr_paths(cls.dfs)
        demo.plot_labyrinth({"klee": cls.klee, "dfs": cls.dfs}, os.path.join(REPORTS, "explore_labyrinth.png"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_klee_finds_every_path(self):
        self.assertIsNone(self.klee.error)
        self.assertEqual(self.klee.errored, 0)
        self.assertEqual(len(self.klee_paths), 256)
        self.assertEqual(len(set(self.klee_paths)), 256)
        for p in self.klee_paths:
            self.assertRegex(p, r"^[LR]{8}$")

    def test_generated_inputs_replay_on_the_real_binary(self):
        """Each solved input, run concretely, takes exactly the path angr said it would."""
        replay = os.path.join(self.workdir, "replay.bin")
        for gen in self.klee.completed:
            with open(replay, "wb") as f:
                f.write(gen.data)
            out = subprocess.run([self.binary, replay], capture_output=True, check=True).stdout
            self.assertEqual(out.splitlines()[0], gen.stdout.splitlines()[0],
                             f"input {gen.data.hex()} replayed to a different path")

    def test_dfs_is_depth_first(self):
        """
        DFS drains one side of the first fork before the other: at most 2 runs of equal
        first decisions, and consecutive paths share most of their prefix.
        """
        self.assertGreaterEqual(len(self.dfs_paths), 32)
        self.assertLessEqual(demo.first_decision_runs(self.dfs_paths), 2)
        self.assertGreaterEqual(demo.mean_common_prefix(self.dfs_paths), 4.0)

    def test_klee_is_not_depth_first(self):
        """
        KLEE's first 64 paths: a random order has about 32.5 first-decision runs (sd ~4), so
        >= 16 is ~4 sd below the mean and DFS's 2 is nowhere close. Two random paths share a
        prefix of about 1 decision; <= 2.5 still sits far below DFS's ~6.
        """
        first64 = self.klee_paths[:64]
        self.assertGreaterEqual(demo.first_decision_runs(first64), 16)
        self.assertLessEqual(demo.mean_common_prefix(first64), 2.5)


@unittest.skipIf(SKIP is not None, SKIP or "")
class LopsidedExploration(unittest.TestCase):
    """
    One long, fork-free path opposite a 256-path subtree. This is what separates KLEE
    random-path from uniform random selection, which labyrinth can't.
    """

    # KLEE finishes the shallow path around step 460; uniform hadn't by step 3000
    MAX_STEPS = 1500

    @classmethod
    def setUpClass(cls):
        cls.workdir = tempfile.mkdtemp(prefix="lopsided_")
        binary = demo.build_target("labyrinth_lopsided", cls.workdir)
        seed_file = demo.zero_seed("labyrinth_lopsided", cls.workdir)
        cls.klee = demo.run("labyrinth_lopsided", binary, seed_file, "klee", SEED, max_steps=cls.MAX_STEPS)
        cls.uniform = demo.run("labyrinth_lopsided", binary, seed_file, "uniform", SEED, max_steps=cls.MAX_STEPS)
        demo.plot_lopsided({"klee": cls.klee, "uniform": cls.uniform},
                           os.path.join(REPORTS, "explore_labyrinth_lopsided.png"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_klee_gives_the_shallow_side_half(self):
        share, window, done = demo.lopsided_shallow_share(self.klee)
        self.assertIsNotNone(done, "KLEE never finished the shallow path")
        self.assertGreater(window, 100)
        self.assertGreater(share, SHALLOW_SHARE_KLEE_MIN)
        self.assertLess(share, 1 - SHALLOW_SHARE_KLEE_MIN)

    def test_uniform_starves_the_shallow_side(self):
        share, _, _ = demo.lopsided_shallow_share(self.uniform)
        self.assertLess(share, SHALLOW_SHARE_UNIFORM_MAX)

    def test_klee_finishes_the_shallow_path_first(self):
        _, _, klee_done = demo.lopsided_shallow_share(self.klee)
        _, _, uniform_done = demo.lopsided_shallow_share(self.uniform)
        self.assertLess(klee_done, uniform_done if uniform_done is not None else self.MAX_STEPS + 1)


def _seed_file(workdir: str, size: int) -> str:
    path = os.path.join(workdir, f"zero_{size}.bin")
    with open(path, "wb") as f:
        f.write(bytes(size))
    return path


@unittest.skipIf(SKIP is not None, SKIP or "")
class ConcolicExploration(unittest.TestCase):
    """
    Concolic exploration: every input byte symbolic, preconstrained to a
    seed, branch flips become new runs.
    """

    @classmethod
    def setUpClass(cls):
        from pyroclastic.magmalyze.angr_concolic_explore import explore
        cls.explore = staticmethod(explore)
        cls.workdir = tempfile.mkdtemp(prefix="seeded_")
        cls.binary = demo.build_target("labyrinth", cls.workdir)
        cls.argv = [cls.binary, "{SYMBOLIC_FILE_PATH}"]
        cls.out = os.path.join(cls.workdir, "out")
        # labyrinth's 8 tests are one loop branch, so lift the per-edge limit and the seed
        # filter to let it enumerate the whole tree
        cls.full = explore(cls.binary, cls.argv, [_seed_file(cls.workdir, 8)],
                           strategy="klee", seed=SEED, max_flips_per_edge=None, seed_coverage_filter=False,
                           output_dirs=(cls.out,), strict=True)
        cls.paths = demo.lr_paths(cls.full)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.workdir, ignore_errors=True)

    def test_finds_every_path_from_one_seed(self):
        self.assertIsNone(self.full.error)
        self.assertEqual(len(self.paths), 256)
        self.assertEqual(len(set(self.paths)), 256)
        # The seed's own path is one of them, and a 256-leaf tree needs exactly 255 flips
        self.assertIn("LLLLLLLL", self.paths)
        self.assertEqual(len(self.full.flips), 255)

    def test_inputs_replay_on_the_real_binary(self):
        replay = os.path.join(self.workdir, "replay.bin")
        for gen in self.full.completed:
            with open(replay, "wb") as f:
                f.write(gen.data)
            out = subprocess.run([self.binary, replay], capture_output=True, check=True).stdout
            self.assertEqual(out.splitlines()[0], gen.stdout.splitlines()[0])

    def test_every_input_is_written_and_logged(self):
        import json
        files = sorted(f for f in os.listdir(self.out) if f.endswith(".bin"))
        # One file per distinct input: a finished path reuses the file its flip wrote
        self.assertEqual(len(files), self.full.files)
        self.assertEqual(len(files), len({g.data for g in self.full.inputs}))
        self.assertTrue(all(g.file and os.path.isfile(g.file) for g in self.full.inputs))
        self.assertFalse([f for f in os.listdir(self.out) if f.endswith(".tmp")])
        with open(os.path.join(self.out, "generated_inputs.jsonl")) as f:
            records = [json.loads(line) for line in f]
        self.assertEqual(sorted(r["file"] for r in records), files)
        self.assertTrue(all(r["seed"] == SEED and r["strategy"] == "klee" for r in records))

    def test_big_seed_still_finds_new_paths(self):
        """
        Why this generalizes to real inputs: a 1000-byte seed where only bytes 0-7 matter.
        Every byte is symbolic, but only input-dependent branches get flipped, so the 992
        unused bytes cost solver time, not search effort: it keeps flipping the branch that
        matters (137 flips in 1000 steps on the 8-byte seed; a full run of the 1000-byte one
        finds all 256 paths but takes ~3 min, so this stops at 1000 steps). Every flip is a
        distinct new input.
        """
        big = _seed_file(self.workdir, 1000)
        result = self.explore(self.binary, self.argv, [big], strategy="klee", seed=SEED,
                              max_flips_per_edge=None, seed_coverage_filter=False, max_steps=1000, strict=True)
        self.assertGreaterEqual(len(result.flips), 50)
        self.assertEqual(len({f.data for f in result.flips}), len(result.flips))
        self.assertTrue(all(len(f.data) == 1000 for f in result.flips))

    def test_solver_timeout_survives_a_flip(self):
        """
        The per-query timeout is set on each seed state, and set again on a flipped state
        (removing the preconstraints rebuilds its solver, which would drop it).
        """
        import angr
        from pyroclastic.magmalyze import angr_concolic_explore as ace
        p = angr.Project(self.binary, auto_load_libs=True, load_debug_info=True)
        state = ace.create_seeded_state(p, [self.binary, ace.SYMBOLIC_FS_PATH],
                                        _seed_file(self.workdir, 8), solver_timeout_ms=1234)
        self.assertEqual(state.solver._solver.timeout, 1234)
        flipper = ace.SeedFlipper(project=p, max_flips_per_edge=None, solver_timeout_ms=1234)
        sm = p.factory.simulation_manager([state], save_unsat=True)
        flipped = []
        while sm.active and not flipped:
            sm.step()
            flipped = flipper.flip(sm.stashes.get('unsat', []))
            sm.drop(stash='unsat')
        self.assertTrue(flipped, "never reached the input-dependent branch")
        self.assertEqual(flipped[0][0].solver._solver.timeout, 1234)

    def test_default_bounds_limit_the_flips(self):
        """
        Defaults: the all-zero seed covers the L edge, so the seed filter leaves only the R
        edge, and max_flips_per_edge=4 allows 4 flips of it.
        """
        bounded = self.explore(self.binary, self.argv, [_seed_file(self.workdir, 8)],
                               strategy="klee", seed=SEED, strict=True)
        self.assertEqual(len(bounded.flips), 4)
        self.assertGreater(bounded.flips_skipped, 0)


SIGTERM_RUNNER = """
import sys
from pyroclastic.magmalyze.angr_concolic_explore import explore
binary, seed_file, out = sys.argv[1:4]
r = explore(binary, [binary, "{SYMBOLIC_FILE_PATH}"], [seed_file], strategy="klee",
            seed=7, max_flips_per_edge=None, seed_coverage_filter=False, output_dirs=(out,))
print("STOPPED_AFTER", r.steps, r.files, flush=True)
"""


@unittest.skipIf(SKIP is not None, SKIP or "")
class StopsCleanlyOnSigterm(unittest.TestCase):
    """
    What SLURM does at a time limit: SIGTERM, then SIGKILL after a grace period. A run must
    stop cleanly on SIGTERM, with everything it found already on disk.
    """

    def test_sigterm_stops_the_run_and_keeps_the_inputs(self):
        import json
        import signal
        import sys
        import time
        workdir = tempfile.mkdtemp(prefix="sigterm_")
        try:
            binary = demo.build_target("labyrinth", workdir)
            out = os.path.join(workdir, "out")
            src = os.path.join(demo.find_repo_root(), "python", "src")
            env = dict(os.environ, PYTHONPATH=src + os.pathsep + os.environ.get("PYTHONPATH", ""))
            proc = subprocess.Popen([sys.executable, "-c", SIGTERM_RUNNER, binary, _seed_file(workdir, 8), out],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, text=True)
            # Wait until it has written a few inputs, i.e. it's mid-exploration, then stop it
            deadline = time.time() + 300
            while time.time() < deadline and proc.poll() is None:
                if os.path.isdir(out) and len([f for f in os.listdir(out) if f.endswith(".bin")]) >= 10:
                    break
                time.sleep(0.5)
            self.assertIsNone(proc.poll(), "the run finished before it could be interrupted")
            proc.send_signal(signal.SIGTERM)
            output, _ = proc.communicate(timeout=120)
            self.assertEqual(proc.returncode, 0, output[-2000:])
            stopped = [line for line in output.splitlines() if line.startswith("STOPPED_AFTER")]
            self.assertTrue(stopped, output[-2000:])
            steps, n_inputs = map(int, stopped[0].split()[1:])
            self.assertLess(steps, 5405, "it ran to completion instead of stopping")
            files = [f for f in os.listdir(out) if f.endswith(".bin")]
            with open(os.path.join(out, "generated_inputs.jsonl")) as f:
                logged = [json.loads(line)["file"] for line in f]
            self.assertEqual(len(files), n_inputs)
            self.assertEqual(sorted(files), sorted(logged))
        finally:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == '__main__':
    unittest.main()
