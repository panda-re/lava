
import struct
import sys
import random 
import psycopg2
import shutil
import subprocess32
import argparse
import json
import os
import shlex
import lockfile
import signal
import atexit
from os.path import basename, dirname, join, abspath

import psycopg2
import threading
import signal
import subprocess32

db_user = "postgres"
db_password = "postgrespostgres"

debugging = True


def get_conn(project):
    conn = psycopg2.connect(host=project['dbhost'], database=project['db'], user=db_user, password=db_password)
    return conn;


def read_i2s(project, tablename):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("select * from %s;" % tablename)
    i2s = {}
    for row in cur:
        i2s[int(row[0])] = row[1]
    return i2s


def next_bug(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("select * from next_bug();")
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return bug


# if updatedb = True, we set inj column. 
def next_bug_random(project, updatedb):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM bug WHERE inj=false OFFSET floor(random() * (SELECT COUNT(*) FROM bug WHERE inj=false) ) LIMIT 1;")
#    cur.execute("select bug_id from bug,dua where (bug.dua_id=dua.dua_id) and (dua.max_liveness=0) and (dua.max_tcn=0);")
#    bugid = cur.fetchone()[0]
#    cur.execute("select * from bug where bug_id=%d" % bugid);
    bug = cur.fetchone()
#    cur.execute("UPDATE bug SET inj=true WHERE bug_id=%d;" % bugid)
    if updatedb:
        cur.execute("UPDATE bug SET inj=true WHERE bug_id={};".format(bug[0]))
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return bug


def get_bug(project,bug_id):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("select * from bug where bug_id=%d;" % bug_id)
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return (bug[1], bug[2])
    


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


def get_atps(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("SELECT * FROM atp;")
    atp = {}
    while True:
        foo = cur.fetchone()
        if foo is None:
            break
        (atp_id, filename_id, line, typ_id, inputfile_id, atp_icount, atp_scount) = foo
        atp[atp_id] = (filename_id, line, typ_id, inputfile_id, atp_icount, atp_scount)
    return atp


def remaining_inj(project):
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("select * from bug where inj=false;")
    return cur.rowcount
        

def ptr_to_set(project, ptr, inputfile_id):
    if ptr == 0: return []
    conn = get_conn(project)
    cur = conn.cursor()
    cur.execute("select * from unique_taint_set where ptr = " + (str(ptr)) + " and inputfile_id = " + str(inputfile_id) + ";")
    (x, file_offsets, ret_inputfile_id) = cur.fetchone()
    assert (x == ptr and inputfile_id == ret_inputfile_id)
    return file_offsets 


class Dua:

    # initialize dua obtaining all info from db
    def __init__(self, project, dua_id, sourcefile, inputfile, lval):
        self.dua_id = dua_id
        self.sourcefile = sourcefile
        self.inputfile = inputfile
        self.lval = lval
        conn = get_conn(project)
        cur = conn.cursor()
        cur.execute("select * from dua where dua_id=%d" % dua_id)
        (x, self.filename_id, self.line, self.lval_id, self.insertionpoint,  \
             self.file_offsets, self.lval_taint, self.inputfile_id, self.max_tcn, \
             self.max_card, self.max_liveness, self.dua_icount, self.dua_scount, self.instr) \
             = cur.fetchone()
        self.instr = int(self.instr)
        # obtain actual taint label sets from db
        n = len(self.lval_taint)
        for i in range(n):
            ptr = self.lval_taint[i]
            self.lval_taint[i] = ptr_to_set(project, ptr, self.inputfile_id)
        assert(x==dua_id)
        self.filename = self.sourcefile[self.filename_id] 
        self.lval = self.lval[self.lval_id]
        self.inputfile = self.inputfile[self.inputfile_id]

    def as_array(self):
        return [self.dua_id, self.filename, self.line, self.lval, \
            self.insertionpoint, self.file_offsets, self.lval_taint, \
            self.inputfile, self.max_tcn, self.max_card, self.max_liveness, \
            self.dua_icount, self.dua_scount]

    def __str__(self):
        return "(" + (",".join([str(e) for e in self.as_array()])) + ")"


class Atp:

    # initialize atp obtaining all info from db
    def __init__(self, project, atp_id, sourcefile, inputfile, atptype):
        self.atp_id = atp_id
        self.sourcefile = sourcefile
        self.inputfile = inputfile
        self.atptype = atptype
        conn = get_conn(project)
        cur = conn.cursor()
        cur.execute("select * from atp where atp_id=%d" % atp_id)
        (x, self.filename_id, self.line, self.typ_id, self.inputfile_id, \
             self.atp_icount, self.atp_scount) \
             = cur.fetchone()
        assert (x==atp_id)
        self.filename = self.sourcefile[self.filename_id]
        self.inputfile = self.inputfile[self.inputfile_id]
        self.typ = self.atptype[self.typ_id]
    
    def as_array(self):
        return [self.atp_id, self.filename, self.line, self.typ, self.inputfile, \
                    self.atp_icount, self.atp_scount]

    def __str__(self):
        return "(" + (",".join([str(e) for e in self.as_array()])) + ")"





class Command(object):
    def __init__(self, cmd, cwd, envv): #  **popen_kwargs):
        self.cmd = cmd
        self.cwd = cwd
        self.envv = envv
        self.process = None
        self.output = "no output"
#        self.popen_kwargs = popen_kwargs

    def run(self, timeout):
        def target():
#            print "Thread started"
            self.process = subprocess32.Popen(self.cmd.split(), cwd=self.cwd, env=self.envv, \
                                                stdout=subprocess32.PIPE, \
                                                stderr=subprocess32.PIPE, \
                                                preexec_fn=os.setsid) # , **popen_kwargs)
            self.output = self.process.communicate()
#            print 'Thread finished'
        thread = threading.Thread(target=target)
        thread.start()
        thread.join(timeout)
        if thread.is_alive():
            if debugging:
                print 'Terminating process cmd=[%s] due to timeout' % self.cmd
            self.process.terminate()
            os.killpg(self.process.pid, signal.SIGTERM) 
            self.process.kill()
            print "terminated"
            thread.join(1)
            self.returncode = -9
        else:
            self.returncode = self.process.returncode
        


def run_cmd(cmd, cw_dir, envv, timeout):
    p = Command(cmd, cw_dir, envv)
    p.run(timeout)
#    p = subprocess32.Popen(cmd.split(), cwd=cw_dir, env=envv, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
    output = p.output  
    exitcode = p.returncode
    if debugging:
        print "run_cmd(" + cmd + ")"
#        print "exitcode = " + str(exitcode)
#        for line in output:
#            print "output = [" + line + "]"
    return (exitcode, output)

def run_cmd_nto(cmd, cw_dir, envv):
    return run_cmd(cmd, cw_dir, envv, 1000000)


lava = 0x6c617661


# fuzz_offsets is a list of tainted byte offsets within file filename.
# replace those bytes with random in a new file named new_filename
def mutfile(filename, lval_taint, new_filename, bug_id):
    magic_val = struct.pack("<I", lava - bug_id)
    # collect set of tainted offsets in file.
    fuzz_offsets = set(sum(lval_taint, []))
    file_bytes = bytearray(open(filename).read())
    # change first 4 bytes in dua to magic value
    for (i, offset) in zip(range(4), fuzz_offsets):
#        print "i=%d offset=%d len(file_bytes)=%d" % (i,offset,len(file_bytes))
        file_bytes[offset] = magic_val[i]
    open(new_filename, "w").write(file_bytes)
