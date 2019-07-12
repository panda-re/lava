#!/usr/bin/env python2

# Parse an lcov file to make a pickle mapping filenames
# to a list of entirely uncovered functions and then a list
# of lines in each of the functions

# Run anywhere (host/docker)

import sys
import pickle

assert(len(sys.argv) == 3), "USAGE: {} gcov_result base_path".format(sys.argv[0])
with open(sys.argv[1]) as infile:
    lines = infile.readlines()

startpath = sys.argv[2]

results = {} # {filename:
                    # uncovered_lines: [1,2,3,...]
                    # funcs: {fun1: {start: X, end: y, uncovlines: [], execs: 0}, ...}

curfile = None
curfunc = None

for line in lines:
    line = line.strip()
    if line.startswith("SF:"):
        if curfile: print(results[curfile]) # Print at the end of each
        curfile = line.split("SF:")[1].replace(startpath, "") # Trim to just filename
        results[curfile] = {"funcs": {}, "uncovered_lines": []}

    elif line.startswith("FN:"):
        (first_loc, func_name) = line.split("FN:")[1].split(",")
        first_loc=int(first_loc)

        for prior_func in results[curfile]["funcs"].keys():
            if results[curfile]["funcs"][prior_func]["end"] == None:
                results[curfile]["funcs"][prior_func]["end"] = first_loc-1 # End the prior func

        results[curfile]["funcs"][func_name] = {"start": first_loc, "end": None,
                                            "uncovlines": [], "execs": False}

    elif line.startswith("FNDA:"):
        (count, func_name) = line.split("FNDA:")[1].split(",")
        count=int(count)
        results[curfile]["funcs"][func_name]["execs"] = count

    elif line.startswith("DA:"):
        (loc, count) = [int(x) for x in line.split("DA:")[1].split(",")]

        # Map this source line back to its containing func
        curfunc = None
        for func, func_data in results[curfile]["funcs"].items():
            if func_data["start"] <= loc and (func_data["end"] is None or func_data["end"] > loc):
                curfunc = func
                break

        if count == 0: # uncov lines is just which lines were uncovered
            assert(curfunc)
            results[curfile]["uncovered_lines"].append(loc)
            results[curfile]["funcs"][curfunc]["uncovlines"].append(loc)



for f, data in results.items():
    #print("\n {}".format(f))
    for func_name, func_data in data["funcs"].items():
        if func_data["execs"] == 0:
            #print(f, func_name, func_data["uncovlines"])
            print(f, func_name, func_data["uncovlines"])

pickle.dump(results, open("uncovered.pickle","wb"))
