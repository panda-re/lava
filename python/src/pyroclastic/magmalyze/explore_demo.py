#!/usr/bin/env python3
"""
See KLEE random-path vs. DFS (and uniform random) with your own eyes, on two tiny targets:

  labyrinth           8 independent byte tests: a balanced tree of 256 paths.
  labyrinth_lopsided  one long, fork-free path opposite a 256-path subtree.

    magmalyze-demo                                  # both targets, klee vs dfs (+uniform)
    magmalyze-demo --target labyrinth --seed 3
    magmalyze-demo --no-show --out test_reports

Run it from a LAVA checkout (it builds the targets from target_bins/*.tar.gz), or point
--repo at one. It prints an ASCII "L/R barcode" in the terminal and, if matplotlib is
installed, saves (and shows) two figures: for labyrinth, an L/R barcode and a grid of when
each leaf finished; for labyrinth_lopsided, the shallow side's share of selections over time.
python/tests/test_explore.py imports the same helpers, so the CI assertions and these
pictures come from the same numbers. Needs angr and a C compiler (cc).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from typing import Optional

TARGETS = {
    # name: number of input bytes the program reads
    "labyrinth": 8,
    "labyrinth_lopsided": 9,
}
COLORS = {"klee": "#10b981", "dfs": "#3b82f6", "uniform": "#f59e0b"}


# --- Building and running --------------------------------------------------------

def find_repo_root(start: Optional[str] = None) -> str:
    """
    The LAVA checkout holding target_bins/labyrinth.tar.gz: the current directory or one of
    its parents (like `lava` finding host.json), else the source tree this module lives in
    (an editable install).
    """
    here = os.path.abspath(start or os.getcwd())
    candidates = [here]
    while os.path.dirname(candidates[-1]) != candidates[-1]:
        candidates.append(os.path.dirname(candidates[-1]))
    # python/src/pyroclastic/magmalyze/ -> the repo root
    candidates.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "..")))
    for root in candidates:
        if os.path.isfile(os.path.join(root, "target_bins", "labyrinth.tar.gz")):
            return root
    raise FileNotFoundError("Can't find target_bins/labyrinth.tar.gz. Run from a LAVA checkout or pass --repo.")


def build_target(name: str, workdir: str, cc: str = "cc", repo_root: Optional[str] = None) -> str:
    """
    Compile <name>.c from target_bins/<name>.tar.gz into workdir and return the binary path.
    The tarball, not the unpacked target_bins/<name>/, is what git tracks (/target_bins/* is
    gitignored), so this is what a fresh CI checkout has.
    """
    repo_root = repo_root or find_repo_root()
    with tarfile.open(os.path.join(repo_root, "target_bins", f"{name}.tar.gz")) as tar:
        source = tar.extractfile(f"{name}/{name}.c").read()
    source_path = os.path.join(workdir, f"{name}.c")
    with open(source_path, "wb") as f:
        f.write(source)
    binary = os.path.join(workdir, name)
    subprocess.check_call([cc, "-O0", "-g", "-o", binary, source_path])
    return binary


def zero_seed(name: str, workdir: str) -> str:
    """The starting input. Any bytes work (flips reach every path); all zeros is simplest."""
    path = os.path.join(workdir, f"{name}_seed.bin")
    with open(path, "wb") as f:
        f.write(bytes(TARGETS[name]))
    return path


def run(name: str, binary: str, seed_file: str, strategy: str, seed: int, max_steps: Optional[int] = None):
    from pyroclastic.magmalyze.angr_concolic_explore import explore
    # No flip limit and no seed filter: every input-dependent branch gets flipped, so the
    # search sees the target's whole tree, the cleanest comparison of the strategies themselves
    return explore(binary, [binary, "{SYMBOLIC_FILE_PATH}"], [seed_file], strategy=strategy, seed=seed,
                   max_steps=max_steps, max_flips_per_edge=None, seed_coverage_filter=False, strict=True)


# --- Metrics (the numbers CI asserts on) --------------------------------------------

def lr_paths(result) -> list[str]:
    """Completed labyrinth paths as L/R strings, in completion order."""
    out = []
    for gen in result.completed:
        line = gen.stdout.decode("utf-8", errors="replace").splitlines()
        if line and line[0] and set(line[0]) <= {"L", "R"}:
            out.append(line[0])
    return out


def first_decision_runs(paths: list[str]) -> int:
    """
    How many runs of equal first decisions in completion order. DFS finishes one side of
    the first fork before the other, so it has at most 2. A random order of n paths
    averages about n/2.
    """
    if not paths:
        return 0
    return 1 + sum(1 for a, b in zip(paths, paths[1:]) if a[0] != b[0])


def mean_common_prefix(paths: list[str]) -> float:
    """
    Mean length of the shared prefix between consecutive completed paths. DFS's neighbors
    share most of their decisions (about depth-2); two random paths share about 1.
    Unlike rank correlation, this doesn't care which child of a fork is tried first, and
    angr's DFS tries them in random order.
    """
    if len(paths) < 2:
        return 0.0
    total = 0
    for a, b in zip(paths, paths[1:]):
        n = 0
        while n < min(len(a), len(b)) and a[n] == b[n]:
            n += 1
        total += n
    return total / (len(paths) - 1)


def _shallow_side(result) -> tuple[Optional[int], int, Optional[int]]:
    """
    labyrinth_lopsided's shallow side: (its label at the first fork, the step the
    measurement window ends, the step its path finished or None). The path is
    (seed, first fork, ...), so the first fork's label is path[1]. If the shallow path
    never finished, it's the first-fork label no deep completion used.
    """
    shallow_done = [g for g in result.completed if g.stdout.startswith(b"S")]
    if shallow_done:
        return shallow_done[0].path[1], shallow_done[0].step, shallow_done[0].step
    deep_labels = {g.path[1] for g in result.completed}
    label = ({0, 1} - deep_labels).pop() if len(deep_labels) == 1 else None
    return label, result.steps, None


def shallow_share_curve(result) -> tuple[list[int], list[float]]:
    """Cumulative shallow-side share after each selection, until the shallow path finishes."""
    label, end, _ = _shallow_side(result)
    xs, ys, hits = [], [], 0
    if label is None:
        return xs, ys
    for step, p in result.selections:
        if len(p) < 2 or step >= end:
            continue
        hits += p[1] == label
        xs.append(step)
        ys.append(hits / len(xs))
    return xs, ys


def lopsided_shallow_share(result) -> tuple[float, int, Optional[int]]:
    """
    For labyrinth_lopsided: the share of selections that went to the shallow side of the
    first fork while that side was still alive, how many selections that covers, and the
    step at which the shallow path finished (None if it never did).
    """
    _, _, done = _shallow_side(result)
    _, ys = shallow_share_curve(result)
    if not ys:
        return float("nan"), 0, done
    return ys[-1], len(ys), done


# --- Text output -----------------------------------------------------------------

def ascii_barcode(paths: list[str], rows: int = 32) -> str:
    """The first `rows` completed paths, one per line: '#' = R, '.' = L."""
    lines = [f"{i:4d}  {p.replace('R', '#').replace('L', '.')}" for i, p in enumerate(paths[:rows])]
    return "\n".join(lines)


# --- Figures ---------------------------------------------------------------------

def plot_labyrinth(results: dict, out_png: str, show: bool = False) -> bool:
    """Panel A: L/R barcode per strategy. Panel B: when each of the 256 leaves finished."""
    try:
        import matplotlib
        if not show:
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False

    names = list(results)
    fig, axes = plt.subplots(2, len(names), figsize=(4.2 * len(names), 8.5), squeeze=False)
    for col, strategy in enumerate(names):
        paths = lr_paths(results[strategy])
        matrix = [[1 if c == "R" else 0 for c in p] for p in paths]
        ax = axes[0][col]
        ax.imshow(matrix, aspect="auto", cmap="Greys", interpolation="nearest")
        ax.set_title(f"{strategy.upper()}: L/R barcode\n"
                     f"first-decision runs={first_decision_runs(paths)}, "
                     f"mean prefix={mean_common_prefix(paths):.2f}", fontsize=9)
        ax.set_xlabel("decision (black = R)")
        ax.set_ylabel("completion order")
        ax.set_xticks(range(8), [str(i + 1) for i in range(8)])

        grid = [[float("nan")] * 16 for _ in range(16)]
        for rank, p in enumerate(paths):
            leaf = int(p.replace("L", "0").replace("R", "1"), 2)
            grid[leaf // 16][leaf % 16] = rank
        ax = axes[1][col]
        im = ax.imshow(grid, cmap="viridis", interpolation="nearest")
        ax.set_title(f"{strategy.upper()}: when each leaf finished", fontsize=9)
        ax.set_xticks([])
        ax.set_yticks([])
        fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="completion order")

    fig.suptitle("labyrinth (balanced, 256 paths)")
    fig.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(out_png)), exist_ok=True)
    fig.savefig(out_png, dpi=130)
    if show:
        plt.show()
    plt.close(fig)
    return True


def plot_lopsided(results: dict, out_png: str, show: bool = False) -> bool:
    """Cumulative share of selections on the shallow side, until the shallow path finishes."""
    try:
        import matplotlib
        if not show:
            matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False

    fig, ax = plt.subplots(figsize=(8, 4.5))
    for strategy, result in results.items():
        xs, ys = shallow_share_curve(result)
        share, window, done = lopsided_shallow_share(result)
        label = f"{strategy}: share={share:.2f}, shallow path " + (f"done at step {done}" if done else "never finished")
        ax.plot(xs, ys, color=COLORS.get(strategy), label=label)
    ax.axhline(0.5, color="grey", linestyle="--", linewidth=0.8)
    ax.set_ylim(-0.02, 1.02)
    ax.set_xlabel("step")
    ax.set_ylabel("share of selections on the shallow side")
    ax.set_title("labyrinth_lopsided: random-path keeps giving the shallow side half")
    ax.legend(fontsize=8)
    fig.tight_layout()
    os.makedirs(os.path.dirname(os.path.abspath(out_png)), exist_ok=True)
    fig.savefig(out_png, dpi=130)
    if show:
        plt.show()
    plt.close(fig)
    return True


# --- CLI -------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--target", choices=["labyrinth", "labyrinth_lopsided", "both"], default="both")
    parser.add_argument("--strategies", default="klee,dfs,uniform", help="comma-separated: klee,dfs,uniform")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--max-steps", type=int, default=None,
                        help="default: run labyrinth to exhaustion, lopsided for 3000 steps")
    parser.add_argument("--out", default="test_reports", help="where to save the PNGs")
    parser.add_argument("--no-show", action="store_true", help="save the figures without opening a window")
    parser.add_argument("--cc", default="cc")
    parser.add_argument("--repo", default=None, help="LAVA checkout with target_bins/ (default: found from the cwd)")
    args = parser.parse_args()

    if shutil.which(args.cc) is None:
        sys.exit(f"No C compiler '{args.cc}' found")
    try:
        repo_root = find_repo_root(args.repo)
    except FileNotFoundError as e:
        sys.exit(str(e))

    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    targets = ["labyrinth", "labyrinth_lopsided"] if args.target == "both" else [args.target]
    workdir = tempfile.mkdtemp(prefix="explore_demo_")
    try:
        for name in targets:
            binary = build_target(name, workdir, args.cc, repo_root)
            seed_file = zero_seed(name, workdir)
            max_steps = args.max_steps if args.max_steps is not None else (None if name == "labyrinth" else 3000)
            results = {s: run(name, binary, seed_file, s, args.seed, max_steps) for s in strategies}

            print("\n" + "=" * 60)
            print(f"{name}  (seed {args.seed}, max_steps {max_steps})")
            print("=" * 60)
            for s, r in results.items():
                if name == "labyrinth":
                    paths = lr_paths(r)
                    print(f"\n{s.upper()}: {len(paths)} paths, first-decision runs={first_decision_runs(paths)}, "
                          f"mean prefix={mean_common_prefix(paths):.2f}  ('#' = R, '.' = L)")
                    print(ascii_barcode(paths))
                else:
                    share, window, done = lopsided_shallow_share(r)
                    print(f"{s:8s} shallow share={share:.3f} over {window} selections, "
                          f"shallow path {'done at step ' + str(done) if done else 'never finished'}")

            png = os.path.join(args.out, f"explore_{name}.png")
            plot = plot_labyrinth if name == "labyrinth" else plot_lopsided
            if plot(results, png, show=not args.no_show):
                print(f"\nFigure saved to {os.path.abspath(png)}")
            else:
                print("\n(matplotlib not installed: skipped the figure)")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    main()
