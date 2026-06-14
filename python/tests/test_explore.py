import os
import unittest
from pyroclastic.utils.vars import LavaPaths

# Import the core engine functions from your module
from pyroclastic.magmalyze.angr_concolic_explore import perform_batch_concolic_exploration
from pyroclastic.magmalyze.coverage import setup as cov_setup, compile as cov_compile


def calculate_randomness_score(paths: list[str]) -> float | int:
    """
    Translates L/R execution paths (e.g. 'LRLRLR') into a spatial
    coordinate on the execution tree, calculating the average step-to-step
    jump distance.
    """
    if len(paths) < 2:
        return 0.0

    path_values = []
    for p in paths:
        bin_str = p.replace('L', '0').replace('R', '1')
        try:
            path_values.append(int(bin_str, 2))
        except ValueError:
            pass

    if len(path_values) < 2:
        return 0.0

    # Calculate absolute differences between consecutive discovered leaves
    deltas = [abs(path_values[i] - path_values[i - 1]) for i in range(1, len(path_values))]
    return sum(deltas) / len(deltas)


def save_test_visualization(paths: list[str], strategy_name: str):
    """
    Saves an execution trace plot to document CI/CD run results.
    Designed to fail gracefully if matplotlib is absent.
    """
    try:
        import matplotlib.pyplot as plt
        y_vals = []
        for p in paths:
            bin_str = p.replace('L', '0').replace('R', '1')
            try:
                y_vals.append(int(bin_str, 2))
            except ValueError:
                pass

        if not y_vals:
            return

        plt.figure(figsize=(8, 4.5))
        plt.plot(range(len(y_vals)), y_vals, marker='o', linestyle='-',
             color='#10b981' if strategy_name == 'klee' else '#3b82f6', alpha=0.8)
        plt.title(f"CI Path Exploration Order: {strategy_name.upper()} Strategy")
        plt.xlabel("Discovery Order Index")
        plt.ylabel("Execution Tree Leaf Coordinate")
        plt.grid(True, linestyle='--', alpha=0.3)

        os.makedirs("test_reports", exist_ok=True)
        plt.savefig(f"test_reports/randomness_graph_{strategy_name}.png", dpi=150)
        plt.close()
    except ImportError:
        pass  # Quietly bypass if matplotlib is missing in CI

class LabyrinthRandomnessTests(unittest.TestCase):
    """
    System and integration tests checking the randomness and path
    dispersion metrics of KLEE exploration versus traditional DFS.
    """

    def setUp(self):
        # 1. Capture the original working directory
        self.original_cwd = os.getcwd()

        # 2. Traverse upwards to discover the repository root (containing host.json or target_bins)
        cwd = self.original_cwd
        repo_root = cwd
        for _ in range(4):
            if os.path.exists(os.path.join(cwd, "host.json")) or os.path.exists(os.path.join(cwd, "target_bins")):
                repo_root = cwd
                break
            cwd = os.path.dirname(cwd)

        # 3. Temporarily shift the working directory to the repo root
        os.chdir(repo_root)

        # 4. Mock the command-line arguments and build LavaPaths
        class MockArgs:
            def __init__(self, project_name="labyrinth"):
                self.project_name = project_name

        args = MockArgs()
        self.lava_paths = LavaPaths(args)

        # 5. Ensure setup and compilation are completed cleanly in the repo root
        cov_setup(self.lava_paths)
        cov_compile(self.lava_paths)

    def tearDown(self):
        # Restore the runner's original directory to keep the environment clean
        os.chdir(self.original_cwd)

    @unittest.skip("Need more testing, will go for FuzzBench now")
    def test_klee_random_search_variance(self):
        """
        CI Integration Test:
        Asserts that KLEERandomSearch meets the required 'random jump' dispersion threshold.
        """
        for run_id in [1, 2, 3]:
            with self.subTest(run_id=run_id):
                # Run KLEE Random Search with 10-second timeout for rapid CI testing
                _, klee_paths = perform_batch_concolic_exploration(
                    self.lava_paths,
                    symbolic_bytes_count=8,
                    timeout=10,
                    strategy="klee"
                )

                self.assertTrue(
                    len(klee_paths) >= 2,
                    f"KLEE did not discover enough branches in run {run_id} to evaluate randomness."
                )

                klee_score = calculate_randomness_score(klee_paths)
                print(f"\n[Run {run_id}] KLEE Randomness Score (Avg Jump): {klee_score:.2f}")

                # Save trace visualization artifacts
                save_test_visualization(klee_paths, f"klee_run_{run_id}")

                # A true random search on an 8-bit depth labyrinth typically yields avg jumps > 30.
                # We assert a highly robust safety margin of > 15 to account for random distribution fluctuations.
                self.assertTrue(
                    klee_score > 15.0,
                    f"KLEE Randomness score was too low ({klee_score:.2f}). Behaving like DFS?"
                )

    @unittest.skip("Need more testing, will go for FuzzBench now")
    def test_dfs_vs_klee_comparison(self):
        """
        CI Comparative Test:
        Verifies that DFS behaves strictly linearly (low jump score)
        compared to the wild leaps of KLEE Random Search.
        """
        # 1. Run DFS
        _, dfs_paths = perform_batch_concolic_exploration(
            self.lava_paths,
            symbolic_bytes_count=8,
            timeout=10,
            strategy="dfs"
        )

        # 2. Run KLEE
        _, klee_paths = perform_batch_concolic_exploration(
            self.lava_paths,
            symbolic_bytes_count=8,
            timeout=10,
            strategy="klee"
        )

        dfs_score = calculate_randomness_score(dfs_paths)
        klee_score = calculate_randomness_score(klee_paths)

        print(f"\n[Comparison] DFS Score: {dfs_score:.2f} | KLEE Score: {klee_score:.2f}")

        save_test_visualization(dfs_paths, "dfs_comparison")
        save_test_visualization(klee_paths, "klee_comparison")

        # DFS should explore adjacent paths (jump score close to 1).
        # KLEE should be exponentially more volatile.
        self.assertTrue(
            klee_score > (dfs_score * 3.0),
            f"KLEE is not significantly more random than DFS! KLEE: {klee_score:.2f}, DFS: {dfs_score:.2f}"
        )


if __name__ == 'main':
    unittest.main()