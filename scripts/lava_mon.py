import os
import re
import glob
import time
import json
import sys
import curses
import subprocess32 as sb
import getpass

from lava import *

log = open ("/tmp/foo-phulin.log", "w")
log_ind = 0
def logp (msg):
    global log_ind
    log.write("%d: %s\n" % (log_ind, msg))
    log.flush()
    log_ind += 1


def dbt_count(tblname):
    conn = get_conn(project)
    cur = conn.cursor()
    sql = "select count(*) from %s;" % tblname
    cur.execute(sql)
    return cur.fetchone()[0]

start_time = time.time()

project = json.load(open(sys.argv[1]))

logdir = "%s/%s/logs" % (project["directory"], project["name"])


ml = (project['buildhost'], "%s/make.log" % logdir)
aql = (project['buildhost'], "%s/add_queries.log" % logdir)
si = project['inputs'][0].replace('/', '-')
bml = (project['pandahost'], "%s/bug_mining-%s.log" % (logdir, si))

# directory tarball explodes into often has version num as part of name
tar_files = sb.check_output(['tar', 'tf', project['tarfile']], stderr=sys.stderr)
target_name = tar_files.splitlines()[0].split(os.path.sep)[0]

(base,iname) = os.path.split(project['inputs'][0])
plog = (project['pandahost'], "%s/%s/queries-%s-%s.iso.plog" % (project['directory'], project['name'], target_name, iname))




# returns when this file exists on this host
def wait_for_file(hostfile):
    (host, filename) = hostfile
    while True:        
        p = sb.Popen("ssh %s ls %s" % (host, filename), shell=True, stdout=sb.PIPE, stderr=sb.PIPE)        
        x = p.communicate()
        if p.returncode == 0:
            return
        time.sleep(0.1)

# returns contents of this file on this host
# but assumes it is there.
def get_file(hostfile):    
    (host, filen) = hostfile
    p = sb.Popen("ssh %s cat %s" % (host, filen), shell=True, stdout=sb.PIPE, stderr=sb.PIPE)
    x = p.communicate()
    if p.returncode == 0:
        # stdout
        return x[0]
    return None


# returns true if patt is in file else false
def find_in_file(patt, hostfile):
    outp = get_file(hostfile)
    if outp is None:
        return None
    res = None
    for line in outp.split('\n'):
        foo = re.search(patt, line)
        if foo:
            return True
    return not (res is None)


# returns either None
# or a list of matches
def find_in_file_extract(patt, hostfile):
    outp = get_file(hostfile)
    if outp is None:
        return None
    res = None
    for line in outp.split('\n'):
        foo = re.search(patt, line)
        if foo:
            if res is None:
                res = []
            res.append(foo.groups()[0])
    return res
    

# check for patt in hostfile and return true if its there 
def check_for(patt, hostfile):
    return find_in_file(patt, hostfile)

def wait_for(patt, hostfile):
    while True:
        if (check_for(patt, hostfile)):
            return 

# extracts last
def extract_float(patt, hostfile):
    assert (check_for(patt, hostfile))
    res = find_in_file_extract(patt, hostfile)
    return float(res[-1])

def extract_int(patt, hostfile):
    res = find_in_file_extract(patt, hostfile)
    return int(res[-1])



def update_elapsed_time(mon):
    return
    global start_time
    el = time.time() - start_time
    mon.addstr(29, 60, "Elapsed time: %.2f" % el)
    mon.refresh()



def monitor_lava(stdscr):

    curses.curs_set(0)
    assert (curses.has_colors())
    
    mon = curses.newwin(30, 80, 4, 4)
    mon.hline(0,1,'-',78)
    mon.hline(29,1,'-',78)
    mon.vline(1,0,'|',28)
    mon.vline(1,79,'|',28)

    v0=2
    mon.addstr(v0, 11, "LAVA: Large-scale Automated Vulnerability Addition", curses.A_BOLD)
    mon.addstr(v0+1, 17, "target: %s" % target_name)
    mon.refresh()

    stage_1_first_time = True

    v1=5
    # stage 1 -- instrument source
    wait_for_file(aql)
    # ok the add queries log file at least exists
    mon.addstr(v1+0, 15, "1. Instrument source w/")
    mon.addstr(v1+1, 15, "   dynamic queries & make")
    mon.refresh()
    # get source lines of code 
    sb.check_call(["tar", "-xf", project['tarfile'], '-C', '/tmp'])
    outp = sb.check_output(['sloccount', "/tmp/%s" % target_name])
    for line in outp.split("\n"):
        foo = re.search("^ansic:\s+([0-9]+) ", line)
        if foo:
            mon.addstr(v0+1, 42, "sloc: " + foo.groups()[0])            
            mon.refresh()

    time.sleep(0.1)

    # wait for add queries to finish
    patt = "add queries complete ([0-9\.]+) seconds"
    wait_for(patt, aql)
    ti = extract_float(patt, aql)
    # grab some neat stats from logfile too
    patt = "num taint queries added ([0-9]+)"
    res = find_in_file_extract(patt, aql)
    # tally up all the queries
    ntq = 0
    for n in res:
        ntq += int(n)
    patt = "num atp queries added ([0-9]+)"
    res = find_in_file_extract(patt, aql)
    natp = 0
    for n in res:
        natp += int(n)
    mon.addstr(v1, 48,   "taint queries: %d" % ntq)
    mon.addstr(v1+1, 48, "  atp queries: %d" % natp)
    mon.refresh()

    time.sleep(0.1)
    update_elapsed_time(mon)

    # stage 2 -- make
    wait_for_file(ml)
    # wait for make to finish
    patt = "make complete ([0-9\.]+) seconds"
    wait_for(patt, ml)

    tm = extract_float(patt, ml)

    mon.addstr(v1, 4, "%4.2fs" % (ti+tm))
    mon.refresh()

#    mon.addstr(9, 4, "%4.2fs" % tm)
    mon.refresh()
    time.sleep(0.1)
    update_elapsed_time(mon)

    # stage 2 -- run instr program & record
    v2=8
    wait_for_file(bml)
    mon.addstr(v2,  15,  "2. Record run of")
    mon.addstr(v2+1, 15, "   instrumented program")
    mon.refresh()
    # wait for record to finish
    patt = "panda record complete ([0-9\.]+) seconds"
    wait_for(patt, bml)
    tr = extract_float(patt, bml)
    mon.addstr(v2, 4, "%4.2fs" % tr)
    mon.refresh()
    
    # stage 3 -- replay + taint
    v3 = 11
    patt = "Adding PANDA arg file_taint:first_instr=([0-9]+)"
    wait_for(patt,bml)
    mon.addstr(v3, 15, "3. Replay with taint")
    mon.addstr(v3+1, 15, "   propagation")
    mon.refresh()
#    time.sleep(10)
    # ok we must be in the 2nd pass replay
    done = False
    while (not done):
        done = check_for("taint analysis complete ([0-9\.]+) seconds", bml)
        if not done:
            logp("still not done")
        patt = "([0-9\.]+)\%\) instr"
        if (check_for(patt, bml)):
            perc = extract_float(patt, bml)
            mon.addstr(v3+1, 35, " %4.2f%%" % perc)
            mon.refresh()
        time.sleep(0.11)
    mon.addstr(v3+1, 35, " 100.00%")
    mon.refresh()
    time.sleep(0.11)
    mon.addstr(v3+1, 35, "        ")
    mon.refresh()
    
    # interestiing stats
    patt = "total_instr in replay:\s+([0-9]+)"
    wait_for(patt, bml)
    ti = extract_int(patt, bml)
    patt = "coverage plugin: total sequential bb for process = ([0-9]+)"
    wait_for(patt, bml)
    sbb = extract_int(patt, bml)
    patt = "coverage plugin: total unique bb for process = ([0-9]+)"
    wait_for(patt, bml)
    ubb = extract_int(patt, bml)
    mon.addstr(v3, 48, "instr: %d" % ti)
    mon.addstr(v3+2, 48,   "  uBB: %d" % ubb)
    mon.addstr(v3+3, 48, "  sBB: %d" % sbb)
    mon.refresh()
    time.sleep(0.11)
    update_elapsed_time(mon)
        
                      
    patt = "taint analysis complete ([0-9\.]+) seconds"
    tt = extract_float(patt, bml)
    mon.addstr(v3, 4, "%4.2fs" % tt)
    mon.refresh()
    update_elapsed_time(mon)

    # figure out how big plog is
    (host, plogfilename) = plog
    outp = sb.check_output(['ssh', host, 'stat', plogfilename])
    for line in outp.split('\n'):
        foo = re.search("Size:\s*([0-9]+)  ", line)
        if foo:
            b = int(foo.groups()[0])
            if foo:
                mon.addstr(v3+1, 48, " plog: %d" % b)
                mon.refresh()
    time.sleep(0.11)
    update_elapsed_time(mon)
    
    # stage 4 -- fbi
    v4 = 16
    mon.addstr(v4, 15,   "4. Analyze taint & find")
    mon.addstr(v4+1, 15, "   bug inject sites")
    mon.refresh()
    # poll db to find out how many dua and atp we have
#    first_db = True
    last_num_dua = 0
    last_num_atp = 0
    last_num_bug = 0
    done = False
    while (not done):
        patt = "fib complete ([0-9\.]+) seconds"
        done = check_for(patt, bml)        
        num_dua = dbt_count("dua")
        num_atp = dbt_count("atp")
        num_bug = dbt_count("bug")
#        if first_db and (num_dua > 0 or num_atp > 0 or num_bug > 0):
#            mon.addstr(v4, 48, "Database")
#            first_db = False
        if num_dua != last_num_dua:
            mon.addstr(v4, 48, " DUAs: %d" % num_dua)
        if num_atp != last_num_atp:
            mon.addstr(v4+1, 48, " ATPs: %d" % num_atp)
        if num_bug != last_num_bug:
            mon.addstr(v4+2, 48, "pBUGs: %d" % num_bug)
        last_num_dua = num_dua
        last_num_atp = num_atp
        last_num_bug = num_bug
        time.sleep(0.1)
        mon.refresh()
    update_elapsed_time(mon)

    tf = extract_float(patt, bml)
    mon.addstr(v4, 4, "%4.2fs" % tf)
    update_elapsed_time(mon)
    mon.refresh()

    # stage 5 inj
    v5=20
    trial=1
    while True:
        # inject trial $trial
        lf = (project['testinghost'], "%s/inject-%d.log" % (logdir, trial))
        logp(str(trial))
        wait_for_file(lf)
        if trial == 1:
            mon.addstr(v5, 15,   "5. Inject bugs &")
            mon.addstr(v5+1, 15,   "   validate")        
        vt=v5+2+trial
        mon.addstr(vt, 15, "   trial %d (100 bugs):" % trial)
        mon.refresh()

        logp("select")
        # select bugs
        patt = "INJECTING BUGS (.*) SOURCE"
        wait_for(patt, lf)
        mon.addstr(vt, 40, "I")
        mon.refresh()

        logp("compile")
        # compile
        patt = "ATTEMPTING BUILD (.*) INJECTED BUG"
        wait_for(patt, lf)
        mon.addstr(vt, 41, "B")
        mon.refresh()

        logp("orig")
        # validate -- does orig input still exit with 0?
        patt = "buggy program succeeds (.*) original input"
        wait_for(patt, lf)
        mon.addstr(vt, 42, "O")
        mon.refresh()

        logp("validate")
        # validate bugs 
        patt = "testing with fuzzed input for" 
        x = check_for(patt, lf)
        wait_for(patt, lf)
        mon.addstr(vt, 43, "V")
        mon.refresh()

        logp("yield")
        patt = "yield ([0-9\.]+) \("
        wait_for(patt, lf)
        y = extract_float(patt, lf)
        mon.addstr(vt, 40, "yield: %.2f" % y)
        mon.refresh()

        patt = "inject complete ([0-9\.]+) seconds" 
        wait_for(patt, lf)
        ti = extract_float(patt, lf)
        mon.addstr(vt, 4, "%.2fs" % ti)
        mon.refresh()

        trial += 1


    while True:
        pass


curses.wrapper(monitor_lava)
