# Magmalyze
This package works with LAVA to generate new random based inputs. 
For exploration techniques, we used Angr perform concolic execution and utilize [KLEE's random path exploration](https://github.com/degrigis/awesome-angr/blob/main/ExplorationTechniques/KLEERandomSearch/KLEERandomSearch.py), see the [paper](https://hci.stanford.edu/cstr/reports/2008-03.pdf).

## Code Coverage
An important aspect of generating new inputs is to measure code coverage. This package uses `coverage.py` to measure code coverage of the C/C++ programs.

To get code coverage for a specific LAVA project, run the following:
```bash
lava-coverage -p <project_name>
```

It will utilize llvm-cov to get code coverage for your project based on the inputs in the `target_configs/<project_name>/inputs` directory.

## Generating new inputs, utilizing concolic execution
An issue about LAVA is that bugs are only injected based on the provided inputs. A [suggestion](https://dl.acm.org/doi/pdf/10.1145/3433210.3453096) 
was to investigate how to get LAVA to inject bugs outside the "main path". We utilize Angr, using KLEE's random search algorithm to get off the "main path", and plant bug in less frequently tested code. 
This improves bug realism, as bugs are more likely to exist in sparsely tested code.


```bash
magmalyze -p <project_name>                                  # KLEE random-path, 1 hour
magmalyze -p <project_name> --seed 7 --max-steps 5000        # reproducible, bounded
magmalyze -p <project_name> --strategy dfs                   # or uniform, for comparison
```

**How it works (concolic execution):** every byte of each seed input is symbolic but
preconstrained to the seed, so each run follows a real path. Whenever a branch that depends on
the input could go the other way, that side is solved into a new concrete input and becomes a
new run. All seeds start the search, and flips are skipped when they lead to an edge the seeds
already cover (`--no-seed-filter` to disable) or past `--max-flips-per-edge` (default 4).
Only branches in the program itself are flipped, not in libc.

Every new input is written the moment it's found, with a line in `generated_inputs.jsonl`
recording where it came from. SIGTERM stops a run cleanly, so on SLURM use
`#SBATCH --signal=TERM@120` to keep everything found before the time limit.

### Where the new inputs go
One `.bin` file per new input (e.g. `gen_<seed>_flip_<run-id>_00042.bin`) plus
`generated_inputs.jsonl`, one line per file saying where it came from (step, seed input, RNG
seed, strategy, run id, angr version). With `--output-dir D`, they go only to `D`. Without it,
they go next to the build's copy of the seeds and to `target_configs/<project>/generated_inputs/`.

### Tune on a 1-hour run before you burn a day
Real targets vary too much for one set of defaults, so run one hour first and read the
progress line it prints every 30 seconds, for example:
```
[*] 1800s | steps 41200 (22.9/s) | live 350 | flips 910 | done 12 | solver timeouts 3 | errored 0 | dropped 0 | rss 3900 MB
```
```bash
magmalyze -p lcms2 --timeout 3600 --seed 1 --output-dir tune/lcms2
```

| Setting | Default | How to pick it from the 1-hour run |
|---|---|---|
| `--timeout` | 3600 s (1 hour) | For the real job, a few minutes under the SLURM `--time` (85800 for 24 h). |
| `--max-live-states` | no cap | Memory per waiting run ≈ (rss at the end − rss at the first line) / live at the end. Set it to (job memory − rss at the first line − a 20% margin) / that. Without a cap, a long run grows until the OOM killer takes it (inputs found so far are still saved). |
| `--solver-timeout` | 30 s per query (claripy's own default is 5 minutes) | A handful of timeouts is fine. If they're a large share of flips, raise it (e.g. 60-120 s): those are the hard branches you want. If steps/s is low and timeouts are rare, lowering it won't help. |
| `--max-flips-per-edge` | 4 | If flips pile up on a few branches (e.g. a byte loop) and new inputs stop reaching new code, lower it. If flips run out early (live drops to 0 before the timeout), raise it or use 0 (unlimited). |
| seed filter | on | Keep it on. `--no-seed-filter` only makes sense to re-explore what the seeds already cover. |

Then check the result before tainting anything: run `lava-coverage` with the generated inputs
and confirm they reach code the seeds don't.

### Long runs and SLURM
The run length is just `--timeout` in seconds (default 3600 = 1 hour). For a 24-hour job, give
angr a bit less than the job's limit, and ask SLURM for SIGTERM a few minutes early as a safety
net. One array task per (target, RNG seed):
```bash
#!/bin/bash
#SBATCH --job-name=magmalyze-lcms2
#SBATCH --time=24:00:00
#SBATCH --signal=TERM@300          # SIGTERM 5 minutes before the limit
#SBATCH --mem=32G
#SBATCH --cpus-per-task=1          # angr is single-threaded
#SBATCH --array=1-10               # 10 independent runs, different RNG seeds
magmalyze -p lcms2 --no-build --timeout 85800 --seed "$SLURM_ARRAY_TASK_ID" \
          --max-live-states 2000 --output-dir "results/lcms2/task$SLURM_ARRAY_TASK_ID"
```
- **Build once first** (`magmalyze -p lcms2 --max-steps 1` on a login or interactive node), then
  submit with `--no-build`. Without it, every task unpacks and builds into the same directory at
  the same time.
- **One `--output-dir` per task.** By default new inputs are also written next to the seeds, so
  a task starting later would pick up other tasks' outputs as seeds and runs wouldn't be
  reproducible. File names also include the SLURM job and task ids.
- **Longer than one job:** start a new job with `--seeds-dir` pointing at a folder holding the
  original seeds plus the previous job's outputs. The seed filter skips everything they already
  reach, so it continues where the last job stopped instead of redoing it.
- **Memory, not CPU, is the limit:** each waiting run is a full angr state. Set
  `--max-live-states` from the job's memory (on labyrinth a state is ~7 MB; real targets are
  bigger, so measure one short run first).

`--strategy klee` is KLEE's random-path selection (Cadar et al., OSDI'08, §3.4) on its own, not
KLEE's default search, which interleaves it with a coverage-optimized searcher. It keeps an
explicit process tree (`ptree.py`) and picks a state by walking from the root, choosing each
fork's children with equal probability. So a part of the program that forks a lot can't starve
one that doesn't. `uniform` (random over live states) and `dfs` use the same tree, so the three
are directly comparable.

To see the difference, run the demo on two tiny targets (needs a C compiler; the figures need
matplotlib):
```bash
magmalyze-demo                                 # from a LAVA checkout, or pass --repo
```
`labyrinth` is a balanced tree of 256 paths: DFS finishes them in a visible depth-first
pattern, KLEE in a scattered order. `labyrinth_lopsided` puts one long, fork-free path opposite
256 short ones. KLEE keeps giving that path half the selections, while uniform random
selection starves it. CI runs the same checks (`python/tests/test_explore.py`) and uploads the
figures as the `explore-figures` artifact.
