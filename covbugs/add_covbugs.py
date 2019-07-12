#!/usr/bin/env python

import pickle
import os
import sys
from subprocess import check_output

# For each uncovered function, try to add a single covbug into it with lavaTool

assert(len(sys.argv) == 3), "USAGE: {} [LavaBase] [SrcRoot]".format(sys.argv[0])
lavaBase = sys.argv[1]
srcRoot = sys.argv[2]

results = pickle.load(open("uncovered.pickle","rb"))
    # {filename:
            # uncovered_lines: [1,2,3,...]
            # uncovered_funcs: {name: [line1, line2...], ...}}

# Generate yaml changes with lavaTool
for f, details in results.items():
    f = os.path.join(srcRoot, f)
    assert os.path.isfile(f), "Couldn't find file {}".format(os.path.join(srcRoot, f))

    if not f.endswith(".c"):
        continue

    # lavaTool filename.c --covbug func_name:l1,l2,l3 
    # should inject a covbug before any returns in l1, l2, or l3
    covbugs = []
    #print(details)
    for fn, func_details in details["funcs"].items():
        if func_details['execs'] == 0: # Uncovered
            newcmd = "{}:[{}]".format(fn, ",".join([str(x) for x in func_details['uncovlines']]))
            covbugs.append(newcmd)

    if len(covbugs):
        cmd = os.path.join(lavaBase, "tools/install/bin/lavaCovBugsLoc") + " {} --funcs={}".format(f, ",".join(covbugs))
        try:
            check_output(cmd, shell=True)
        except Exception as e:
            print(e)

# Actually apply changes
