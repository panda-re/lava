import psycopg2
import shutil
import subprocess

debugging = False
db_host = "18.126.0.46"
db = "tshark"
db_user = "lava"
db_password = "llaavvaa"

sourcefile = {}
inputfile = {}
lval = {}
atptype = {}

home_dir = "/home/tleek"
target_dir = home_dir + "/lava/src-to-src/wireshark-1.8.2"
query_build = target_dir + "/wireshark-1.8.2.orig"
git_dir = home_dir + "/git"
lava_tool = git_dir + "/lava/src_clang/build/lavaTool"

# bugs_build dir assumptions
# 1. we have run configure
# 2. we have run make and make install
# 3. compile_commands.json exists in bugs build dir and refers to files in the bugs_build dir
bugs_build = target_dir + "/wireshark-1.8.2.bugs"

lavadb = home_dir + "/tshark-lavadb"


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


def remaining_inj():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("select * from bug where inj=false;")
    return cur.rowcount


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
             self.file_offsets, self.lval_offsets, self.inputfile_id, self.max_tcn, \
             self.max_card, self.max_liveness, self.dua_icount, self.dua_scount) \
             = cur.fetchone()
        assert(x==dua_id)
        self.filename = self.sourcefile[self.filename_id] 
        self.lval = self.lval[self.lval_id]
        self.inputfile = self.inputfile[self.inputfile_id]

    def as_array(self):
        return [self.dua_id, self.filename, self.line, self.lval, \
            self.insertionpoint, self.file_offsets, self.lval_offsets, \
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

def run_cmd(cmd, cw_dir):
    if cw_dir:
        p = subprocess.Popen(cmd.split(), cwd=cw_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    make_safe_copy(filename_bug_part)
    cmd = lava_tool + ' -action=inject -bug-list=\"' + str(bug_id) \
        + '\" -lava-db=' + lavadb + ' -p ' + bugs_build \
        + " -bug-build-dir=" + bugs_build \
        + ' ' + filename_bug_part 
    run_cmd(cmd, None)






sourcefile = read_i2s("sourcefile")
inputfile = read_i2s("inputfile")
lval = read_i2s("lval")
atptype = read_i2s("atptype")

print remaining_inj()
(score, bug_id, dua_id, atp_id) = next_bug()
dua = Dua(dua_id, sourcefile, inputfile, lval)
atp = Atp(atp_id, sourcefile, inputfile, atptype)

print "------------\n"
print "SELECTED BUG: " + str(bug_id)
print "   score=%d " % score
print "   (%d,%d)" % (dua_id, atp_id)
print "DUA:"
print "   " + str(dua)
print "ATP:"
print "   " + str(atp)

print "------------\n"
print "INJECTING BUGS INTO SOURCE"
# modify src @ the dua to siphon off tainted bytes into global
inject_bug_part_into_src(bug_id, dua.filename)

# modify src the atp to use that global
inject_bug_part_into_src(bug_id, atp.filename)


# compile
print "------------\n"
print "ATTEMPTING BUILD OF INJECTED BUG"
(rv, outp) = run_cmd("make", bugs_build)
if rv==0:
    # success
    print "build succeeded"
    (rv, outp) = run_cmd("make install", bugs_build)
    # really how can this fail if build succeeds?
    assert (rv == 0)
    print "make install succeeded"
else:
    # build failed
    print "build failed"
    # log that to db

revert_to_safe_copy(bugs_build + "/" + dua.filename)
revert_to_safe_copy(bugs_build + "/" + atp.filename)



# add a row to the build table in the db
#add_build_row([bug_id], success, binpath)
 

#if success:
    # build succeeded -- try to run in
    # first, create a modified input
#    for 
#    pass
