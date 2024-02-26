import os
import sys
import json
import numpy
from tabulate import tabulate

from db import *

tcns = [1, 10, 100, 1000]
# tcns = [1,4,16,64,256,1024,4096]
livs = tcns

INFINITY = 100000000000000


# returns true iff i[0] <= x < i[1]
def interval_check(x, i):
    if (i[0] <= x) and (x < i[1]):
        return True
    return False


def get_interval(i, partition):
    if i == 0:
        return 0, partition[i]
    elif i == len(partition):
        return partition[i - 1], INFINITY
    return partition[i - 1], partition[i]


def spelunk(json_filename, counts, totals):
    project = json.load(open(json_filename))
    db = project['db']
    runs = get_runs(project)
    builds = get_builds(project)
    bugs = get_bugs(project)
    duas = get_duas(project)
    # result #1: 
    # write max_liveness & max_tcn to two different files,
    # one for when we succeed instantiating a segfault ("-sf") 
    # and one for when we don't succeed ("-nf")
    (head, tail) = os.path.split(json_filename)
    fs = open("%s/%s-res-sf" % (project['directory'], tail), "w")
    ff = open("%s/%s-res-nf" % (project['directory'], tail), "w")
    # keep track of unique duas involved in working buffer overflow
    bo_duas = set([])
    bo_atps = set([])
    bo_srcfiles = set([])
    for run_id in runs.keys():
        (build_id, fuzz, exitcode, output_lines, success) = runs[run_id]
        if fuzz:
            (buglist, binpath, compiles) = builds[build_id]
            bug_id = buglist[0]
            (dua_id, atp_id, inj) = bugs[bug_id]
            (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, \
             max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = duas[dua_id]
            if exitcode == -11 or exitcode == -6:
                fs.write("%d %d\n" % (max_liveness, max_tcn))
                # high liveness yet we were able to trigger a segfault?  Weird
                if max_liveness > 100 or max_tcn > 100:
                    print("run=%d bug=%d dua=%d is weird -- max_tcn=%d max_liveness=%d" % (
                    run_id, bug_id, dua_id, max_tcn, max_liveness))
                bo_duas.add(dua_id)
                bo_atps.add(atp_id)
                bo_srcfiles.add(filename_id)
            else:
                ff.write("%d %d\n" % (max_liveness, max_tcn))

            # check that exitcode == 0 for un-fuzzed frun
            # n^2 oops!
            for run_id2 in runs.keys():
                (build_id2, fuzz2, exitcode2, output_lines2, success2) = runs[run_id]
                if build_id2 == build_id and fuzz2 == False:
                    assert (exitcode2 == 0)
    fs.close()
    ff.close()
    print("%s -- %d unique srcfiles involved in a validated bug" % (project['name'], len(bo_srcfiles)))
    print("%s -- %d unique duas involved in a validated bug" % (project['name'], len(bo_duas)))
    print("%s -- %d unique atps involved in a validated bug" % (project['name'], len(bo_atps)))

    max_tcns = {}
    max_lvns = {}
    max_crds = {}
    for i in range(1 + len(tcns)):
        if not (i in counts):
            counts[i] = {}
            totals[i] = {}
        tcn_interval = get_interval(i, tcns)
        for j in range(1 + len(livs)):
            # for all runs with max_liveness in liv_interval and max_tcn in tcn_interval
            # collect counts by exit code
            if not (j in counts[i]):
                counts[i][j] = {}
                totals[i][j] = 0
            # for all runs with max_liveness in liv_interval and max_tcn in tcn_interval
            # collect counts by exit code
            liv_interval = get_interval(j, livs)
            n = 0
            for run_id in runs.keys():
                (build_id, fuzz, exitcode, output_lines, success) = runs[run_id]
                (buglist, binpath, compiles) = builds[build_id]
                # NB: assuming just one bug inserted per run! 
                assert (len(buglist) == 1)
                bug_id = buglist[0]
                (dua_id, atp_id, inj) = bugs[bug_id]
                (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, \
                 max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = duas[dua_id]
                if fuzz:
                    if (interval_check(max_liveness, liv_interval)) and (interval_check(max_tcn, tcn_interval)):
                        if not (exitcode in counts[i][j]):
                            counts[i][j][exitcode] = 1
                        else:
                            counts[i][j][exitcode] += 1
                        totals[i][j] += 1


counts = {}
totals = {}
for json_filename in (sys.argv[1:]):
    print("\nspelunk [%s]\n" % json_filename)
    spelunk(json_filename, counts, totals)

table = []

for i in range(1 + len(tcns)):
    tcn_interval = get_interval(i, tcns)
    row = []
    if tcn_interval[1] == INFINITY:
        row.append("tcn=[%d,+inf]" % tcn_interval[0])
    else:
        row.append("tcn=[%d,%d)" % (tcn_interval[0], tcn_interval[1]))
    for j in range(1 + len(livs)):
        liv_interval = get_interval(j, livs)
        ys = "y=u"
        if totals[i][j] > 0:
            nsf = 0
            if -11 in counts[i][j]:
                nsf = counts[i][j][-11]
            if -6 in counts[i][j]:
                nsf += counts[i][j][-6]
            y = (float(nsf)) / totals[i][j]
            ys = "y=%.3f" % y
        cell = "n=%d %7s" % (totals[i][j], ys)
        row.append(cell)
    table.append(row)

headers = []
for j in range(1 + len(livs)):
    liv_interval = get_interval(j, livs)
    if liv_interval[1] == INFINITY:
        headers.append("liv=[%d..+inf]" % liv_interval[0])
    else:
        headers.append("liv=[%d..%d)" % (liv_interval[0], liv_interval[1]))

# headers = ["liv=[%d..%d)" % l for l in livs]

print(tabulate(table, headers, tablefmt="grid"))
