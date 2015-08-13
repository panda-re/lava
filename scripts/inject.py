#!/usr/bin/python

import sys
import random 
import psycopg2
import shutil
import subprocess32
import argparse
import json
import os
import shlex
from os.path import basename, dirname, join, abspath

project = None

debugging = False

def get_conn():
    conn = psycopg2.connect(host=db_host, database=db, user=db_user, password=db_password)
    return conn;


def read_i2s(tablename):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from %s;" % tablename)
    i2s = {}
    for row in cur:
        i2s[int(row[0])] = row[1]
    return i2s


def next_bug():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from next_bug();")
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return bug

def next_bug_random():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM bug WHERE inj=false OFFSET floor(random() * (SELECT COUNT(*) FROM bug WHERE inj=false) ) LIMIT 1;");
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return bug



def get_bug(bug_id):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from bug where bug_id=%d;" % bug_id)
    bug = cur.fetchone()
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return (bug[1], bug[2])
    


def remaining_inj():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from bug where inj=false;")
    return cur.rowcount


def ptr_to_set(ptr, inputfile_id):
    if ptr == 0: return []
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from unique_taint_set where ptr = " + (str(ptr)) + " and inputfile_id = " + str(inputfile_id) + ";")
    (x, file_offsets, ret_inputfile_id) = cur.fetchone()
    assert (x == ptr and inputfile_id == ret_inputfile_id)
    return file_offsets 


class Dua:

    # initialize dua obtaining all info from db
    def __init__(self, dua_id, sourcefile, inputfile, lval):
        self.dua_id = dua_id
        self.sourcefile = sourcefile
        self.inputfile = inputfile
        self.lval = lval
        conn = get_conn()
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
            self.lval_taint[i] = ptr_to_set(ptr, self.inputfile_id)
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
    def __init__(self, atp_id, sourcefile, inputfile, atptype):
        self.atp_id = atp_id
        self.sourcefile = sourcefile
        self.inputfile = inputfile
        self.atptype = atptype
        conn = get_conn()
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


# p =  "/a/b/c/d"
# fn = "/a/b/c/d/e/f/g"
# returns "e/f/g"
# so, the end part of fn after the common prefix p (minus leading '/')
# note that if p isnt a prefix of fn then the assert will fail
def filename_suff(p, fn):
    n = fn.find(p)
    assert(n==0)
    l = len(p)
    suff = fn[l:]
    while suff[0] == '/':
        suff = suff[1:]
    return suff

def run_cmd(cmd, cw_dir,envv):
    p = subprocess32.Popen(cmd.split(), cwd=cw_dir, env=envv, stdout=subprocess32.PIPE, stderr=subprocess32.PIPE)
    output = p.communicate()
    exitcode = p.returncode
    if debugging:
        print "run_cmd(" + cmd + ")"
        print "exitcode = " + str(exitcode)
        for line in output:
            print "output = [" + line + "]"
    return (exitcode, output)

def make_safe_copy(fn):
    shutil.copyfile(fn, fn + ".sav")

def revert_to_safe_copy(fn):
    shutil.copyfile(fn + ".sav", fn)


def inject_bug_part_into_src(bug_id, suff):
    global query_build
    global bugs_build
    global lavatoll
    global lavadb
    filename_bug_part = bugs_build + "/" + suff
#    make_safe_copy(filename_bug_part)
    cmd = lava_tool + ' -action=inject -bug-list=\"' + str(bug_id) \
        + '\" -lava-db=' + lavadb + ' -p ' + bugs_build \
        + ' ' + filename_bug_part \
        + ' ' + '-project-file=' + project_file
    run_cmd(cmd, None, None)




def add_build_row(bugs, compile_succ):
    conn = get_conn()
    cur = conn.cursor()
    # NB: ignoring binpath for now
    sql = "INSERT into build (bugs,compile) VALUES (ARRAY" + (str(bugs)) + "," + (str(compile_succ)) + ") RETURNING build_id;"
    print sql    
    cur.execute(sql)
    build_id = cur.fetchone()[0]
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()
    return build_id


def get_suffix(fn):
    split = basename(fn).split(".")
    if len(split) == 1:
        return ""
    else:
        return "." + split[-1]

# fuzz_offsets is a list of tainted byte offsets within file filename.
# replace those bytes with random in a new file named new_filename
def mutfile(filename, lval_taint, new_filename):
    # collect set of tainted offsets in file.
    fuzz_offsets = set(sum(lval_taint, []))
    file_bytes = bytearray(open(filename).read())

    # change first 4 bytes to "lava"
    for (i, offset) in zip(range(4), fuzz_offsets):
        file_bytes[offset] = "lava"[i]
    open(new_filename, "w").write(file_bytes)

# here's how to run the built program
def run_prog(install_dir, input_file):
    cmd = project['command'].format(install_dir=install_dir,input_file=input_file)
    print cmd
    envv = {}
    envv["LD_LIBRARY_PATH"] = join(install_dir, project['library_path'])
    return run_cmd(cmd,install_dir,envv)

import string

def printable(text):
    import string
    # Get the difference of all ASCII characters from the set of printable characters
    nonprintable = set([chr(i) for i in range(256)]).difference(string.printable)
    return ''.join([ '.' if (c in nonprintable)  else c for c in text])


def add_run_row(build_id, fuzz, exitcode, lines, success):
    lines = lines.translate(None, '\'\"')
    lines = printable(lines[0:1024])
    conn = get_conn()
    cur = conn.cursor()
    # NB: ignoring binpath for now
    sql = "INSERT into run (build_id, fuzz, exitcode, output_lines, success) VALUES (" + (str(build_id)) + "," + (str(fuzz)) + "," + (str(exitcode)) + ",\'" + lines + "\'," + (str(success)) + ");"
    print sql    
    cur.execute(sql)
    # need to do all three of these in order for the writes to db to actually happen
    cur.close()
    conn.commit()
    conn.close()



if __name__ == "__main__":    

    next_bug_db = False
    parser = argparse.ArgumentParser(description='Inject and test LAVA bugs.')
    parser.add_argument('project', type=argparse.FileType('r'),
            help = 'JSON project file')
    parser.add_argument('bugid', nargs='?', type=int, default=-1,
            help = 'Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('-r', '--randomize', action='store_true', default = False,
            help = 'Choose the next bug randomly rather than by score')
    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # Set up our globals now that we have a project

    db_host = project['dbhost']
    db = project['db']
    db_user = "postgres"
    db_password = "postgrespostgres"

    sourcefile = {}
    inputfile = {}
    lval = {}
    atptype = {}

    # This is top-level directory for our LAVA stuff.
    top_dir = join(project['directory'], project['name'])
    lava_dir = dirname(dirname(abspath(sys.argv[0])))
    lava_tool = join(lava_dir, 'src_clang', 'build', 'lavaTool')

    # bugs_build dir assumptions
    # 1. we have run configure
    # 2. we have run make and make install
    # 3. compile_commands.json exists in bugs build dir and refers to files in the bugs_build dir
    bugs_parent = join(top_dir, 'bugs')
    try:
        os.makedirs(bugs_parent)
    except: pass

    tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']], stderr=sys.stderr)
    bugs_root = tar_files.splitlines()[0].split(os.path.sep)[0]

    queries_build = join(top_dir, bugs_root)
    bugs_build = join(bugs_parent, bugs_root)
    bugs_install = join(bugs_build, 'lava-install')
    # Make sure directories and btrace is ready for bug injection.
    def run(args, **kwargs):
        subprocess32.check_call(args, cwd=bugs_build,
                stdout=sys.stdout, stderr=sys.stderr, **kwargs)
    if not os.path.exists(bugs_build):
        subprocess32.check_call(['tar', 'xf', project['tarfile'],
            '-C', bugs_parent], stderr=sys.stderr)
    if not os.path.exists(join(bugs_build, '.git')):
        run(['git', 'init'])
        run(['git', 'add', '-A', '.'])
        run(['git', 'commit', '-m', 'Unmodified source.'])
    if not os.path.exists(join(bugs_build, 'btrace.log')):
        run(shlex.split(project['configure']) + ['--prefix=' + bugs_install])
        run([join(lava_dir, 'btrace', 'sw-btrace')] + shlex.split(project['make']))
    if not os.path.exists(join(bugs_build, 'compile_commands.json')):
        run([join(lava_dir, 'btrace', 'sw-btrace-to-compiledb'),
                '/home/moyix/git/llvm/Debug+Asserts/lib/clang/3.6.1/include'])
        run(['git', 'add', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json.'])
    if not os.path.exists(bugs_install):
        run(project['install'], shell=True)

    lavadb = join(top_dir, 'lavadb')

    # Now start picking the bug and injecting
    if args.bugid != -1:
        bug_id = int(args.bugid)
        score = 0
        (dua_id, atp_id) = get_bug(bug_id)
    elif args.randomize:
        print "Remaining to inject:", remaining_inj()
        print "Using strategy: random"
        (bug_id, dua_id, atp_id, inj) = next_bug_random()
        next_bug_db = True
    else:
        # no args -- get next bug from postgres
        print "Remaining to inject:", remaining_inj()
        print "Using strategy: score"
        (score, bug_id, dua_id, atp_id) = next_bug()
        next_bug_db = True

    sourcefile = read_i2s("sourcefile")
    inputfile = read_i2s("inputfile")
    lval = read_i2s("lval")
    atptype = read_i2s("atptype")

    print "------------\n"
    print "SELECTED BUG: " + str(bug_id)
    if not args.randomize: print "   score=%d " % score
    print "   (%d,%d)" % (dua_id, atp_id)

    dua = Dua(dua_id, sourcefile, inputfile, lval)
    atp = Atp(atp_id, sourcefile, inputfile, atptype)

    print "DUA:"
    print "   " + str(dua)
    print "ATP:"
    print "   " + str(atp)

    # cleanup
    print "------------\n"
    print "CLEAN UP SRC"
    run_cmd("/usr/bin/git checkout -f", bugs_build, None)
    # ugh -- with tshark if you *dont* do this, your bug-inj source may not build, sadly
    # it looks like their makefile doesn't understand its own dependencies, in fact
    #run_cmd("make clean", bugs_build, None)


    print "------------\n"
    print "INJECTING BUGS INTO SOURCE"
    inject_files = set([dua.filename, atp.filename, project['main_file']])
    # modify src @ the dua to siphon off tainted bytes into global
    # modify src the atp to use that global
    # modify main to include lava_set
    # only if they are in different files
    for f in inject_files:
        print "injecting code into [%s]" % f
        inject_bug_part_into_src(bug_id, f)

    # compile
    print "------------\n"
    print "ATTEMPTING BUILD OF INJECTED BUG"
    print "build_dir = " + bugs_build
    (rv, outp) = run_cmd(project['make'] + " -j12", bugs_build, None)
    build = False
    if rv!=0:
        # build failed
        print outp
        print "build failed"    
    else:
        # build success
        build = True
        print "build succeeded"
        (rv, outp) = run_cmd("make install", bugs_build, None)
        # really how can this fail if build succeeds?
        assert (rv == 0)
        print "make install succeeded"

    # add a row to the build table in the db    
    if next_bug_db:
        build_id = add_build_row([bug_id], build)
        print "build_id = %d" % build_id
    if build:
        try:
            # build succeeded -- testing
            print "------------\n"
            # first, try the original file
            print "TESTING -- ORIG INPUT"
            orig_input = join(top_dir, 'inputs', dua.inputfile)
            print orig_input
            (rv, outp) = run_prog(bugs_install, orig_input)
            print "retval = %d" % rv
            print "output:"
            lines = outp[0] + " ; " + outp[1]
            print lines
            if next_bug_db:
                add_run_row(build_id, False, rv, lines, True)
            print "SUCCESS"
            # second, fuzz it with the magic value
            print "TESTING -- FUZZED INPUT"
            suff = get_suffix(orig_input)
            pref = orig_input[:-len(suff)] if suff != "" else orig_input
            fuzzed_input = "{}-fuzzed-{}{}".format(pref, bug_id, suff)
            print "fuzzed = [%s]" % fuzzed_input
            mutfile(orig_input, dua.lval_taint, fuzzed_input)
            (rv, outp) = run_prog(bugs_install, fuzzed_input)
            print "retval = %d" % rv
            print "output:"
            lines = outp[0] + " ; " + outp[1]
            print lines
            if next_bug_db:        
                add_run_row(build_id, True, rv, lines, True)
            print "TESTING COMPLETE"
            # NB: at the end of testing, the fuzzed input is still in place
            # if you want to try it 
        except:
            print "TESTING FAIL"
            if next_bug_db:
                add_run_row(build_id, False, 1, "", True)
            raise




    # cleanup
#    print "------------\n"
#    print "CLEAN UP SRC"
#    run_cmd("/usr/bin/git checkout -f", bugs_build, None)
#    revert_to_safe_copy(bugs_build + "/" + dua.filename)
#    revert_to_safe_copy(bugs_build + "/" + atp.filename)
