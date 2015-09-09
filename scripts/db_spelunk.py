import sys
import json
import psycopg2
import numpy
from tabulate import tabulate


def get_conn():
    conn = psycopg2.connect(host=db_host, database=db, user=db_user, password=db_password)
    return conn;


def get_runs():
    conn = get_conn()
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

def get_builds():
    conn = get_conn()
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


def get_bugs():
    conn = get_conn()
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

def get_duas():
    conn = get_conn()
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


project = json.load(open(sys.argv[1]))
        

db_host = project['dbhost']
db = project['db']
db_user = "postgres"
db_password = "postgrespostgres"



runs = get_runs()
builds = get_builds()
bugs = get_bugs()
duas = get_duas()

max_tcns = {}
max_lvns = {}
max_crds = {}

tcns = [1,4,16,64,256,1024,4096]
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
#        print "tcn: " + (str(tcn_interval))
#        print "liv: " + (str(liv_interval))
        c_exit = {}
        n=0
        for run_id in runs.keys():
            (build_id, fuzz, exitcode, output_lines, success) = runs[run_id]
            (buglist, binpath, compiles) = builds[build_id]
            bug_id = buglist[0]
            (dua_id, atp_id, inj) = bugs[bug_id]
            (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, \
                 max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = duas[dua_id]
            if fuzz:
                if (interval_check(max_liveness, liv_interval)) and (interval_check(max_tcn, tcn_interval)):
                    if not (exitcode in c_exit):
                        c_exit[exitcode] = 1
                    else:
                        c_exit[exitcode] += 1
                    n += 1
        ys = "y=u"
        if (n > 0):
            nsf = 0
            if -11 in c_exit:
                nsf = c_exit[-11]
            y = (float(nsf)) / n
            ys = "y=%.3f" % y
        cell = "n=%d %7s" % (n,ys)
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
