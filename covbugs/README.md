Guide to adding coverage bugs

# Motivation 
LAVA can only add bugs to paths we know how to explore.
By adding simple bugs to functions we can't get to, we can try getting comeptitiors to generate inputs to improve our coverage.

# Process
## Build target
Build a bug-free, non-preprocessed, version of the target binary. Modify the makefile to also log coverage information by adding `--coverage -fprofile-arcs -ftest-coverage` to CFLAGS

## Collect all coverage
Modify `cov.sh` in order to measure total coverage across all submitted inputs for all versions of the target program. This will probably take a few hours.
Example usage: `cov.sh file/file-5.35/ file/inputs/*`

## Parse coverage data
Run `parse_cov.py` to transform lcov's output into a python pickle `uncovered.pickle` which identifies all uncovered functions and their lines
In docker, run `add_covbugs.py` to generate yaml for all bugs.
In docker, in the target soruce directory, run `clang-apply-replacements .` to update the source

## Produce buggy target
Make the target and fuzz it for a bit to see we find some of the bugs
