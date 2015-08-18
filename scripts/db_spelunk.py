import sys
import json
import psycopg2
import numpy


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
for run_id in runs.keys():
     (build_id, fuzz, exitcode, output_lines, success) = runs[run_id]
     (buglist, binpath, compiles) = builds[build_id]
     bug_id = buglist[0]
     (dua_id, atp_id, inj) = bugs[bug_id]
     (filename_id, line, lval_id, insertionpoint, file_offset, lval_taint, inputfile_id, max_tcn, max_card, max_liveness, dua_icount, dua_scount, instr) = duas[dua_id]
     if fuzz:
         if not exitcode in max_tcns:
             max_tcns[exitcode] = []
             max_lvns[exitcode] = []
         max_tcns[exitcode].append(max_tcn)
         max_lvns[exitcode].append(max_liveness)

for exitcode in max_tcns:
    mt = numpy.array(max_tcns[exitcode])
    ml = numpy.array(max_lvns[exitcode])
    print "exitcode=%4d n=%5d max_tcn = (%.2f +/ %.2f)  max_lvn = (%.2f +/ %.2f)" % (exitcode, len(mt), mt.mean(), mt.std(), ml.mean(), ml.std())

