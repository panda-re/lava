import os
import sys
import json
import psycopg2
import numpy
from tabulate import tabulate


db_user = "postgres"
db_password = "postgrespostgres"


def get_conn(project):
    conn = psycopg2.connect(host=project['dbhost'], database=project['db'], user=db_user, password=db_password)
    return conn;


def get_runs(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM run where fuzz=true;")
    run = {}
    while True:
        foo = cur.fetchone()
        if foo is None: 
            break
        (run_id, build_id, fuzz, exitcode, output_lines, success) = foo
        run[run_id] = (build_id, fuzz, exitcode, output_lines, success)
    return run

def get_builds(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM build;")
    build = {}
    while True:
        foo = cur.fetchone()
        if foo is None: 
            break
        (build_id, bugs, binpath, compiles) = foo        
        build[build_id] = (bugs, binpath, compiles)
    return build;


def get_bugs(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM bug;")
    bug = {}
    while True:
        foo = cur.fetchone()
        if foo is None: 
            break
        (bug_id, dua_id, atp_id, inj) = foo
        bug[bug_id] = (dua_id, atp_id, inj)
    return bug;

def get_duas(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM dua;")
    dua = {}
    while True:
        foo = cur.fetchone()
        if foo is None: 
            break
        (dua_id, filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = foo   
        dua[dua_id] = (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr)
    return dua





tcns = [1,10,100]
#tcns = [1,4,16,64,256,1024,4096]
livs = tcns

INFINITY = 100000000000000

# returns true iff i[0] <= x < i[1]
def interval_check(x, i):
    if (i[0] <= x) and (x < i[1]):
        return True
    return False

def get_interval(i, partition):
    if i==0:
        return (0,partition[i])
    elif i == len(partition):
        return (partition[i-1], INFINITY)
    return (partition[i-1], partition[i])


def spelunk(json_filename, counts, totals):
    project = json.load(open(json_filename))
    db_host = project['dbhost']
    db = project['db']
    runs = get_runs(project)
    builds = get_builds(project)
    bugs = get_bugs(project)
    duas = get_duas(project)
    # result #1: 
    # write max_liveness & max_tcn to two different files,
    # one for when we succeed instantiating a segfault ("-sf") 
    # and one for when we don't succeed ("-nf")
    (head,tail) = os.path.split(json_filename)
    fs = open("%s/%s-res-sf" % (project['directory'], tail), "w")
    ff = open("%s/%s-res-nf" % (project['directory'], tail), "w")
    for run_id in runs.keys():
        (build_id, fuzz, exitcode, output_lines, success) = runs[run_id]
        if fuzz:
            (buglist, binpath, compiles) = builds[build_id]
            bug_id = buglist[0]
            (dua_id, atp_id, inj) = bugs[bug_id]
            (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, \
                 max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = duas[dua_id]
            if (exitcode == -11):
                fs.write("%d %d\n" % (max_liveness, max_tcn))
                # high liveness yet we were able to trigger a segfault?  Weird
#                if max_liveness > 100:
#                    print "run=%d bug=%d  dua=%d is weird" % (run_id, bug_id,dua_id)
            else:
                ff.write("%d %d\n" % (max_liveness, max_tcn))
    fs.close()
    ff.close()
    max_tcns = {}
    max_lvns = {}
    max_crds = {}
    for i in range(1+len(tcns)):    
        if not (i in counts):
            counts[i] = {}
            totals[i] = {}
        tcn_interval = get_interval(i, tcns)
        for j in range(1+len(livs)):
            # for all runs with max_liveness in liv_interval and max_tcn in tcn_interval
            # collect counts by exit code
            if not (j in counts[i]):
                counts[i][j] = {}
                totals[i][j] = 0
            # for all runs with max_liveness in liv_interval and max_tcn in tcn_interval
            # collect counts by exit code
            liv_interval = get_interval(j, livs)
            n=0
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
    print "\nspelunk [%s]\n" % json_filename
    spelunk(json_filename, counts, totals)


table = []

for i in range(1+len(tcns)):    
    tcn_interval = get_interval(i, tcns)
    row = []
    if tcn_interval[1] == INFINITY:
        row.append("tcn=[%d,+inf]" % tcn_interval[0])
    else:
        row.append("tcn=[%d,%d)" % (tcn_interval[0],tcn_interval[1]))
    for j in range(1+len(livs)):
        liv_interval = get_interval(j, livs)
        ys = "y=u"
        if (totals[i][j] > 0):
            nsf = 0
            if -11 in counts[i][j]:
                nsf = counts[i][j][-11]
            y = (float(nsf)) / totals[i][j]
            ys = "y=%.3f" % y
        cell = "n=%d %7s" % (totals[i][j],ys)
        row.append(cell)
    table.append(row)


headers = []
for j in range(1+len(livs)):
    liv_interval = get_interval(j, livs)
    if liv_interval[1] == INFINITY:
        headers.append("liv=[%d..+inf]" % liv_interval[0])
    else:
        headers.append("liv=[%d..%d)" % (liv_interval[0], liv_interval[1]))

#headers = ["liv=[%d..%d)" % l for l in livs]

print tabulate(table, headers, tablefmt="grid")
