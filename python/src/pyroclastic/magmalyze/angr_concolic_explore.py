#!/usr/bin/env python

import angr
import claripy
import os
import argparse
import json
import shlex
import signal
import threading
import time
import logging
import random
import traceback
from dataclasses import dataclass, field
from typing import Callable, Optional
from angr.exploration_techniques import ExplorationTechnique
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_manager.py#L27
from angr.sim_manager import SimulationManager
# https://github.com/angr/angr/blob/9fa64a7ce22a4ca3f43e159cb4a831ce586a3241/angr/sim_state.py#L60
from angr.sim_state import SimState
from ..magmalyze.ptree import PTree, PTreeNode

logging.getLogger('angr').setLevel(logging.ERROR)
logging.getLogger('pyvex').setLevel(logging.ERROR)
logging.getLogger('claripy').setLevel(logging.ERROR)

logger = logging.getLogger(__name__)
SYMBOLIC_FS_PATH = '/tmp/input.txt'
STRATEGIES = ("klee", "uniform", "dfs")
# Seconds per solver query. claripy's own default is 5 minutes, which lets one hard query
# stall a run; tune it on a short run (see the README).
DEFAULT_SOLVER_TIMEOUT = 30


@dataclass
class Completion:
    """
    A path that ran to termination: when it finished, where it sits in the tree, and its
    input/output. The state itself is dropped as soon as this is taken, to save memory.
    """
    step: int
    path: tuple
    data: bytes
    stdout: bytes
    origin: str

    @classmethod
    def of(cls, step: int, path: tuple, state: SimState) -> "Completion":
        return cls(step, path, state.solver.eval(state.globals['sym_content'], cast_to=bytes),
                   state.posix.dumps(1), state.globals.get('origin_seed', 'unknown'))


@dataclass
class Flip:
    """A branch flip: a new concrete input, taken the moment it was found."""
    step: int
    path: tuple
    data: bytes
    origin: str
    edge: tuple


def _edges(state: SimState) -> set:
    addrs = list(state.history.bbl_addrs) + [state.addr]
    return set(zip(addrs, addrs[1:]))


class SeedFlipper:
    """
    Concolic execution. Every input byte is symbolic but preconstrained
    to a concrete input, so a run follows that input's path, and the other side of each
    symbolic branch comes back from angr as an unsat successor. flip() turns such a successor
    into a new concolic run: drop the preconstraints, check the branch is really feasible,
    solve for a concrete input, and preconstrain to it. The search then treats it as just
    another child of a fork.

    seed_edges:          edges the seed inputs already cover; flips toward them are skipped,
                         so effort goes to what no input reaches. None disables the filter.
    max_flips_per_edge:  flip a (source block, target block) edge at most this many times over
                         the whole run, across all seeds. None = unlimited.
    solver_timeout_ms:   per-query solver timeout; a flip whose query times out is skipped
                         (counted in timed_out) instead of stalling the run.
    """

    SYSTEM_PREFIXES = ("/lib", "/usr/lib", "/lib64", "/usr/lib64")

    def __init__(self, seed_edges: Optional[set] = None, max_flips_per_edge: Optional[int] = 4,
                 project: Optional[angr.Project] = None, solver_timeout_ms: Optional[int] = None):
        self.seed_edges = seed_edges
        self.max_flips_per_edge = max_flips_per_edge
        self.project = project
        self.solver_timeout_ms = solver_timeout_ms
        self.flip_counts: dict[tuple, int] = {}
        self.skipped = 0
        self.timed_out = 0

    def in_target(self, addr: int) -> bool:
        """
        Only flip branches in the program under test: the main binary and its own libraries,
        not libc/the loader (whose data-dependent branches on the input, e.g. inside fread,
        would otherwise dominate the flips) or angr's stubs.
        """
        if self.project is None:
            return True
        obj = self.project.loader.find_object_containing(addr)
        if obj is None:
            return False
        if obj is self.project.loader.main_object:
            return True
        path = getattr(obj, "binary", None)
        return bool(path) and not os.path.realpath(path).startswith(self.SYSTEM_PREFIXES)

    def flip(self, unsat_states: list) -> list[tuple[SimState, bytes, tuple]]:
        flipped = []
        for state in unsat_states:
            edge = (state.history.addr, state.addr)
            if not self.in_target(edge[0]):
                self.skipped += 1
                continue
            # Only branches whose condition depends on the input are real flips. Others (a
            # loop counter, the stack-canary check) can look satisfiable once the
            # preconstraints are gone, and would fork runs that take the same path.
            guard = state.history.jump_guard
            sym = state.globals['sym_content']
            if guard is None or not guard.symbolic or not (guard.variables & sym.variables):
                self.skipped += 1
                continue
            if self.seed_edges is not None and edge in self.seed_edges:
                self.skipped += 1
                continue
            if self.max_flips_per_edge is not None and self.flip_counts.get(edge, 0) >= self.max_flips_per_edge:
                self.skipped += 1
                continue
            state.preconstrainer.remove_preconstraints()
            # remove_preconstraints() leaves its bookkeeping behind; clear it so the new
            # preconstraint below isn't reported as a duplicate
            state.preconstrainer.preconstraints = []
            state.preconstrainer.variable_map = {}
            # Removing the preconstraints rebuilds the solver, which drops its timeout
            set_solver_timeout(state, self.solver_timeout_ms)
            try:
                if not state.satisfiable():
                    # Infeasible even without the seed, not just for this seed
                    continue
                data = state.solver.eval(sym, cast_to=bytes)
            except claripy.errors.ClaripySolverInterruptError:
                self.timed_out += 1
                continue
            state.preconstrainer.preconstrain(claripy.BVV(data), sym)
            self.flip_counts[edge] = self.flip_counts.get(edge, 0) + 1
            flipped.append((state, data, edge))
        return flipped


class PTreeSearch(ExplorationTechnique):
    """
    Explore through an explicit process tree, stepping ONE state per step.

    strategy:
      "klee"    KLEE random-path selection (Cadar et al., OSDI'08, §3.4): walk the tree from
                the root, picking a child uniformly at each fork. The algorithm itself.
      "uniform" Uniform random over live states. Random, but not KLEE (baseline).
      "dfs"     Depth-first, trying a fork's children in random order, like angr's DFS.

    All three share the same tree and bookkeeping, so their selection and completion logs
    are directly comparable. Every selection is logged as (step, tree path).

    With a flipper, branch flips join the fork as extra children (that's concolic execution;
    without one, it forks on every symbolic branch, which the unit tests use). max_live_states
    caps memory: past it, the oldest waiting leaves are dropped, which loses nothing already
    found, because each flip's input is kept when it's made.
    """

    def __init__(self, strategy: str = "klee", seed: Optional[int] = None,
                 flipper: Optional[SeedFlipper] = None, max_live_states: Optional[int] = None,
                 on_input: Optional[Callable] = None):
        super().__init__()
        if strategy not in STRATEGIES:
            raise ValueError(f"Unknown strategy {strategy!r}, pick one of {STRATEGIES}")
        self.strategy = strategy
        self.rng = random.Random(seed)
        self.tree = PTree()
        self.current: Optional[PTreeNode] = None
        self.step_count = 0
        self.selections: list[tuple[int, tuple]] = []
        self.completions: list[Completion] = []
        self.errored = 0
        self.flipper = flipper
        self.flips: list[Flip] = []
        self.max_live_states = max_live_states
        self.dropped = 0
        # Called with each new GeneratedInput the moment it's found (a finished path or a
        # flip), so a run killed early (e.g. by SLURM) has already saved everything so far
        self.on_input = on_input

    def _complete(self, path: tuple, state: SimState):
        c = Completion.of(self.step_count, path, state)
        self.completions.append(c)
        if self.on_input is not None:
            self.on_input(GeneratedInput(path=c.path, data=c.data, stdout=c.stdout, origin=c.origin,
                                         complete=True, step=c.step, kind="done"))

    def _flipped(self, path: tuple, state: SimState, data: bytes, edge: tuple):
        f = Flip(self.step_count, path, data, state.globals.get('origin_seed', 'unknown'), edge)
        self.flips.append(f)
        if self.on_input is not None:
            self.on_input(GeneratedInput(path=f.path, data=f.data, stdout=b"", origin=f.origin,
                                         complete=False, step=f.step, kind="flip"))

    def setup(self, simgr: SimulationManager):
        for state in simgr.stashes['active']:
            self.tree.add_root(state)
        self._select(simgr, 'active')

    def _select(self, simgr: SimulationManager, stash: str):
        if self.strategy == "klee":
            leaf = self.tree.select_random_path(self.rng)
        elif self.strategy == "uniform":
            leaf = self.tree.select_uniform(self.rng)
        else:
            leaf = self.tree.select_dfs()
        self.current = leaf
        if leaf is None:
            simgr.stashes[stash] = []
            return
        self.selections.append((self.step_count, leaf.path))
        simgr.stashes[stash] = [leaf.state]

    def step(self, simgr: SimulationManager, stash: str = 'active', **kwargs):
        leaf = self.current
        if leaf is None:
            return simgr
        dead_before = len(simgr.stashes['deadended'])
        errored_before = len(simgr.errored)

        simgr = simgr.step(stash=stash, **kwargs)
        self.step_count += 1

        # Only the selected state was active, so everything new came from it
        alive = list(simgr.stashes[stash])
        finished = simgr.stashes['deadended'][dead_before:]
        self.errored += len(simgr.errored) - errored_before

        flipped = []
        if self.flipper is not None:
            flipped = self.flipper.flip(simgr.stashes.get('unsat', []))
            simgr.drop(stash='unsat')
        flip_info = {id(state): (data, edge) for state, data, edge in flipped}

        successors = alive + [state for state, _, _ in flipped] + finished
        if len(successors) >= 2:
            children = self.tree.fork(leaf, successors,
                                      order_rng=self.rng if self.strategy == "dfs" else None)
            for child in children:
                if id(child.state) in flip_info:
                    self._flipped(child.path, child.state, *flip_info[id(child.state)])
                elif any(child.state is s for s in finished):
                    self._complete(child.path, child.state)
                    self.tree.kill(child)
            self._enforce_cap()
        elif len(alive) == 1:
            self.tree.advance(leaf, alive[0])
        else:
            for state in finished:
                self._complete(leaf.path, state)
            self.tree.kill(leaf)
        # Everything needed from finished states is in self.completions now
        simgr.drop(stash='deadended')

        self._select(simgr, stash)
        return simgr

    def _enforce_cap(self):
        if self.max_live_states is None:
            return
        while len(self.tree) > self.max_live_states:
            self.tree.kill(self.tree.oldest_leaf())
            self.dropped += 1

    def live_states(self) -> list[tuple[tuple, SimState]]:
        return [(leaf.path, leaf.state) for leaf in self.tree.leaves()]


@dataclass
class GeneratedInput:
    path: tuple
    data: bytes
    stdout: bytes
    origin: str
    complete: bool
    step: Optional[int] = None
    file: Optional[str] = None
    # "done" (a finished path) or "flip" (a flipped branch: a new input, taken when found)
    kind: str = "done"


@dataclass
class ExplorationResult:
    strategy: str
    seed: Optional[int]
    steps: int
    elapsed: float
    selections: list[tuple[int, tuple]]
    inputs: list[GeneratedInput] = field(default_factory=list)
    errored: int = 0
    error: Optional[str] = None
    flips_skipped: int = 0
    dropped: int = 0
    # Distinct inputs (= files written per output directory)
    files: int = 0
    solver_timeouts: int = 0
    peak_rss_mb: int = 0

    @property
    def completed(self) -> list[GeneratedInput]:
        """Complete paths only, in the order they finished."""
        return [i for i in self.inputs if i.complete]

    @property
    def flips(self) -> list[GeneratedInput]:
        return [i for i in self.inputs if i.kind == "flip"]


class InputSink:
    """
    Writes each new input to every output directory the moment it's found, so a run that's
    killed (SLURM time limit, OOM) keeps everything up to that point. Each file is written
    to a temp name and renamed, so a kill never leaves a half-written input.

    Files are de-duplicated by content; records are not. A finished path's
    input is the same bytes its flip already wrote, so its "done" record points at that
    existing file instead of writing a copy. Every directory gets one line per FILE in
    generated_inputs.jsonl: file, kind, step, tree path, source seed, and run_info (the RNG
    seed, strategy, run id), so every generated input is attributable later.
    """

    def __init__(self, output_dirs: tuple = (), run_id: str = "run", run_info: Optional[dict] = None):
        self.dirs = list(output_dirs)
        self.run_id = run_id
        self.run_info = run_info or {}
        self.files: dict[bytes, Optional[str]] = {}
        self.inputs: list[GeneratedInput] = []
        for d in self.dirs:
            os.makedirs(d, exist_ok=True)

    def add(self, gen: GeneratedInput) -> bool:
        """Record gen; write it if its bytes are new. Returns whether a file was written."""
        self.inputs.append(gen)
        if gen.data in self.files:
            gen.file = self.files[gen.data]
            return False
        name = f"gen_{gen.origin}_{gen.kind}_{self.run_id}_{len(self.files):05d}.bin"
        self.files[gen.data] = None
        for d in self.dirs:
            path = os.path.join(d, name)
            with open(path + ".tmp", "wb") as fd:
                fd.write(gen.data)
            os.replace(path + ".tmp", path)
            with open(os.path.join(d, "generated_inputs.jsonl"), "a") as log:
                log.write(json.dumps({"file": name, "kind": gen.kind, "step": gen.step, "path": list(gen.path),
                                      "origin": gen.origin, **self.run_info}) + "\n")
            gen.file = gen.file or path
        self.files[gen.data] = gen.file
        return True


def peak_rss_mb() -> int:
    """This process's peak memory so far, in MB (0 where the resource module is missing)."""
    try:
        import resource
    except ImportError:
        return 0
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss // 1024


def set_solver_timeout(state: SimState, timeout_ms: Optional[int]):
    """
    Per-query solver timeout in ms (claripy's default is 300000, 5 minutes). A query that
    times out raises ClaripySolverInterruptError: during a step, angr moves that state to the
    errored stash; during a flip, the flip is skipped.
    """
    if timeout_ms is not None:
        state.solver._solver.timeout = timeout_ms


def create_seeded_state(project: angr.Project, actual_argv: list[str], input_file_path: str,
                        solver_timeout_ms: Optional[int] = None):
    """
    EVERY byte of the file is symbolic, preconstrained to the seed's
    bytes, so the run follows the seed's path.
    """
    with open(input_file_path, 'rb') as fd:
        concrete = fd.read() or b"\x00"
    sym = claripy.BVS(f'sym_{os.path.basename(input_file_path)}', len(concrete) * 8)
    simfile = angr.SimFile(SYMBOLIC_FS_PATH, content=sym, size=len(concrete))
    state = project.factory.full_init_state(
        args=actual_argv,
        fs={SYMBOLIC_FS_PATH: simfile},
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ALL_FILES_EXIST
        }
    )
    set_solver_timeout(state, solver_timeout_ms)
    state.preconstrainer.preconstrain(claripy.BVV(concrete), sym)
    state.globals['sym_content'] = sym
    state.globals['origin_seed'] = os.path.basename(input_file_path)
    print(f"[*] State Initialized: {os.path.basename(input_file_path)} ({len(concrete)} bytes, "
          f"all symbolic, preconstrained to the seed)")
    return state


def trace_seed_edges(project: angr.Project, states: list, max_steps: Optional[int] = None) -> set:
    """
    Run each seeded state along its seed's own path (preconstrained, so it doesn't fork) and
    return the union of edges they cover. This is what the seed set already reaches.
    """
    edges = set()
    for state in states:
        sm = project.factory.simulation_manager(state.copy())
        steps = 0
        while sm.active and (max_steps is None or steps < max_steps):
            sm.step()
            steps += 1
        for s in sm.active + sm.deadended:
            edges |= _edges(s)
    return edges


def make_run_id() -> str:
    """
    A per-run tag for output file names: time + pid, plus the SLURM job/array ids when set, so
    parallel array jobs writing to one directory never collide.
    """
    parts = [time.strftime('%Y%m%d-%H%M%S'), str(os.getpid())]
    job = os.environ.get("SLURM_ARRAY_JOB_ID") or os.environ.get("SLURM_JOB_ID")
    if job:
        parts.append(f"j{job}")
    task = os.environ.get("SLURM_ARRAY_TASK_ID")
    if task:
        parts.append(f"t{task}")
    return "-".join(parts)


def explore(binary_path: str, argv: list[str], seed_files: list[str], strategy: str = "klee",
            seed: Optional[int] = None, max_steps: Optional[int] = None, timeout: Optional[float] = None,
            max_flips_per_edge: Optional[int] = 4, seed_coverage_filter: bool = True,
            max_live_states: Optional[int] = None, output_dirs: tuple = (),
            solver_timeout: Optional[float] = DEFAULT_SOLVER_TIMEOUT,
            strict: bool = False) -> ExplorationResult:
    """
    Concolic exploration of binary_path from seed_files: every input byte
    symbolic, preconstrained to each seed, so runs follow real paths; each input-dependent
    branch that could go the other way becomes a new input and a new run. max_flips_per_edge
    and seed_coverage_filter bound the flips (see SeedFlipper); max_live_states caps memory;
    solver_timeout (seconds per solver query, None = claripy's 5 minutes) keeps one hard
    query from stalling the run.

    argv is the full command line; the argument "{SYMBOLIC_FILE_PATH}" is replaced by the
    symbolic file. The seed makes a run reproducible (it drives the path selection).
    max_steps (steps = one basic block of one state) and timeout (seconds) bound the run;
    with neither, it runs until every path terminates.

    result.inputs holds finished paths and flips in the order they were found. Each input is
    written to every directory in output_dirs as soon as it's found, one file per distinct
    content (see InputSink); result.files counts them.

    An exception during exploration is logged and the inputs found so far are still
    returned (result.error is set), unless strict=True, which re-raises it.
    """
    rng = random.Random(seed)
    p = angr.Project(binary_path, auto_load_libs=True, load_debug_info=True)
    actual_argv = [arg.replace("{SYMBOLIC_FILE_PATH}", SYMBOLIC_FS_PATH) for arg in argv]

    timeout_ms = int(solver_timeout * 1000) if solver_timeout else None
    print(f"[*] Initializing fleet with {len(seed_files)} seeds...")
    initial_states = [create_seeded_state(p, actual_argv, f, timeout_ms) for f in seed_files]
    seed_edges = None
    if seed_coverage_filter:
        seed_edges = trace_seed_edges(p, initial_states, max_steps)
        print(f"[*] The seeds cover {len(seed_edges)} edges; flips toward those are skipped")
    flipper = SeedFlipper(seed_edges=seed_edges, max_flips_per_edge=max_flips_per_edge, project=p,
                          solver_timeout_ms=timeout_ms)
    sm = p.factory.simulation_manager(initial_states, save_unsat=True)

    run_id = make_run_id()
    sink = InputSink(output_dirs, run_id=run_id,
                     run_info={"run_id": run_id, "seed": seed, "strategy": strategy,
                               "binary": os.path.basename(binary_path), "angr": angr.__version__})
    technique = PTreeSearch(strategy, seed=rng.randrange(2**32), flipper=flipper,
                            max_live_states=max_live_states, on_input=sink.add)
    sm.use_technique(technique)
    print(f"[*] Strategy: {strategy} | seed: {seed} | max_steps: {max_steps} | timeout: {timeout}")

    start_time = time.time()
    last_print = start_time

    # SLURM sends SIGTERM at the time limit (earlier with #SBATCH --signal=TERM@<secs>), then
    # SIGKILL after a grace period. Treat it as "stop now": inputs are already on disk.
    # Signals can only be set from the main thread, so elsewhere this is skipped.
    terminated = {"flag": False}

    def on_sigterm(signum, frame):
        terminated["flag"] = True
        print("\n[!] SIGTERM received (time limit?): stopping after this step...")

    previous_handler = None
    if threading.current_thread() is threading.main_thread():
        previous_handler = signal.signal(signal.SIGTERM, on_sigterm)

    def progress_callback(mgr):
        # One line per 30 s with everything the README's "tune on a 1-hour run" section uses
        nonlocal last_print
        now = time.time()
        if now - last_print > 30:
            elapsed_s = max(now - start_time, 1e-9)
            print(f"[*] {int(elapsed_s)}s | steps {technique.step_count} ({technique.step_count / elapsed_s:.1f}/s) | "
                  f"live {len(technique.tree)} | flips {len(technique.flips)} | done {len(technique.completions)} | "
                  f"solver timeouts {flipper.timed_out} | errored {technique.errored} | "
                  f"dropped {technique.dropped} | rss {peak_rss_mb()} MB", flush=True)
            last_print = now
        return mgr

    def should_stop(mgr):
        if terminated["flag"]:
            return True
        if max_steps is not None and technique.step_count >= max_steps:
            return True
        return timeout is not None and (time.time() - start_time) > timeout

    error = None
    try:
        sm.run(until=should_stop, step_func=progress_callback)
    except KeyboardInterrupt:
        print("\n[!] User interrupted (CTRL+C). Proceeding to save discovered paths...")
    except Exception as e:
        if strict:
            raise
        error = f"{type(e).__name__}: {e}"
        print(f"\n[!] Exploration stopped by an error, saving what was found so far:\n{traceback.format_exc()}")
    finally:
        if previous_handler is not None:
            signal.signal(signal.SIGTERM, previous_handler)

    elapsed = time.time() - start_time
    result = ExplorationResult(strategy=strategy, seed=seed, steps=technique.step_count, elapsed=elapsed,
                               selections=technique.selections, inputs=sink.inputs,
                               errored=technique.errored, error=error,
                               flips_skipped=flipper.skipped, dropped=technique.dropped,
                               files=len(sink.files), solver_timeouts=flipper.timed_out,
                               peak_rss_mb=peak_rss_mb())
    print(f"\n[*] Exploration ended after {technique.step_count} steps in {elapsed:.1f}s"
          f"{' (SIGTERM)' if terminated['flag'] else ''}: {len(result.completed)} complete paths, "
          f"{len(result.flips)} flips, {result.files} distinct inputs "
          f"({result.flips_skipped} flips skipped, {result.solver_timeouts} solver timeouts, "
          f"{result.errored} errored, {result.dropped} states dropped for memory, "
          f"peak rss {result.peak_rss_mb} MB).")
    return result


def perform_batch_concolic_exploration(project_paths, timeout: int = 3600, strategy: str = "klee",
                                       seed: Optional[int] = None, max_steps: Optional[int] = None,
                                       max_flips_per_edge: Optional[int] = 4, seed_coverage_filter: bool = True,
                                       max_live_states: Optional[int] = None, seeds_dir: Optional[str] = None,
                                       output_dir: Optional[str] = None,
                                       solver_timeout: Optional[float] = DEFAULT_SOLVER_TIMEOUT) -> ExplorationResult:
    """
    Explore a LAVA project's built binary. Seeds come from seeds_dir, or by default the copy of
    the project's inputs/ next to the build. New inputs go to output_dir, or by default next to
    those seeds plus a backup in <config_dir>/generated_inputs.
    """
    full_cmd_str = project_paths.config['command'].format(
        install_dir=shlex.quote(str(project_paths.generate_executable_install_dir)),
        input_file="{SYMBOLIC_FILE_PATH}"
    ).strip()
    argv_template = shlex.split(full_cmd_str)

    inputs_directory = seeds_dir or project_paths.generate_directory_inputs_path
    seed_files = []
    if os.path.isdir(inputs_directory):
        # Everything in the directory is a seed, except this tool's own log and temp files
        seed_files = sorted(os.path.join(inputs_directory, f) for f in os.listdir(inputs_directory)
                            if os.path.isfile(os.path.join(inputs_directory, f))
                            and f != "generated_inputs.jsonl" and not f.endswith(".tmp"))
    if not seed_files:
        raise RuntimeError(f"No input files found in {inputs_directory}")

    if output_dir:
        output_dirs = (output_dir,)
    else:
        output_dirs = (inputs_directory, os.path.join(project_paths.config['config_dir'], 'generated_inputs'))
    result = explore(argv_template[0], argv_template, seed_files, strategy=strategy, seed=seed,
                     max_steps=max_steps, timeout=timeout, max_flips_per_edge=max_flips_per_edge,
                     seed_coverage_filter=seed_coverage_filter, max_live_states=max_live_states,
                     output_dirs=output_dirs, solver_timeout=solver_timeout)

    print("\n" + "=" * 40)
    print("      PATH DISCOVERY TRACE")
    print("=" * 40)
    for n, gen in enumerate(result.completed):
        out = gen.stdout.decode('utf-8', errors='replace').strip().splitlines()
        print(f"[{n:03d}] step {gen.step}: {out[0][:60] if out else '(no stdout)'}  <- ({os.path.basename(gen.file or '')})")
    print("=" * 40)
    print(f"[*] Saved {result.files} input files ({len(result.completed)} complete paths, {len(result.flips)} flips) "
          f"to {', '.join(output_dirs)}")
    return result


def main():
    from ..magmalyze.coverage import setup, compile
    from ..utils.vars import LavaPaths

    parser = argparse.ArgumentParser(description="Generate new inputs for a LAVA project with concolic execution "
                                                 "(KLEE random-path search).")
    parser.add_argument("--project", "-p", required=True, dest="project_name", help="Provide the LAVA project name")
    parser.add_argument("--timeout", "-t", type=int, default=3600,
                        help="seconds (default 1 hour); for a SLURM job, a little under its --time")
    parser.add_argument("--max-steps", type=int, default=None, help="Stop after this many steps")
    parser.add_argument("--strategy", choices=STRATEGIES, default="klee", help="Choose exploration strategy")
    parser.add_argument("--seed", type=int, default=None, help="RNG seed, for reproducible runs")
    parser.add_argument("--max-flips-per-edge", type=int, default=4,
                        help="flip each branch edge at most N times (0 = unlimited)")
    parser.add_argument("--no-seed-filter", action="store_true",
                        help="also flip toward edges the seeds already cover")
    parser.add_argument("--max-live-states", type=int, default=None,
                        help="memory cap: most waiting runs kept (default: no cap; see the README)")
    parser.add_argument("--solver-timeout", type=float, default=DEFAULT_SOLVER_TIMEOUT,
                        help=f"seconds per solver query (default {DEFAULT_SOLVER_TIMEOUT}; 0 = claripy's 5 minutes)")
    parser.add_argument("--seeds-dir", default=None,
                        help="read seeds from here instead of the project's inputs/ (e.g. to add an "
                             "earlier run's outputs)")
    parser.add_argument("--output-dir", default=None,
                        help="write new inputs only here (give each SLURM task its own)")
    parser.add_argument("--no-build", action="store_true",
                        help="reuse the existing build instead of unpacking and building again "
                             "(for SLURM array tasks, after one build)")
    args = parser.parse_args()
    lava_paths = LavaPaths(args)
    if args.no_build:
        install_dir = lava_paths.generate_project_root_unpacked_tar_directory / "lava-install"
        if not install_dir.is_dir():
            raise SystemExit(f"--no-build: no build at {install_dir}. Run once without --no-build first.")
        lava_paths.generate_executable_install_dir = install_dir
        lava_paths.generate_directory_inputs_path = os.path.join(install_dir, 'inputs')
    else:
        setup(lava_paths)
        compile(lava_paths)

    perform_batch_concolic_exploration(
        lava_paths,
        timeout=args.timeout,
        strategy=args.strategy,
        seed=args.seed,
        max_steps=args.max_steps,
        max_flips_per_edge=args.max_flips_per_edge or None,
        seed_coverage_filter=not args.no_seed_filter,
        max_live_states=args.max_live_states,
        solver_timeout=args.solver_timeout or None,
        seeds_dir=args.seeds_dir,
        output_dir=args.output_dir,
    )


if __name__ == '__main__':
    main()
