import getpass
import os
import re
import time
import json
import sys
import curses
import subprocess32 as sb

from os.path import basename, join

from lava import LavaDatabase, AttackPoint, Bug, Dua, Build, Run, get_suffix

log = open ("/tmp/lava-demo-{}.log".format(getpass.getuser()), "w")
log_ind = 0
def logp (msg):
    global log_ind
    log.write("%d: %s\n" % (log_ind, msg))
    log.flush()
    log_ind += 1

start_time = time.time()

project = json.load(open(sys.argv[1]))

project_dir = join(project["directory"], project["name"])
log_dir = join(project_dir, "logs")

make_log = join(log_dir, "make.log")
add_queries_log = join(log_dir, "add_queries.log")
input_file = project['inputs'][0].replace('/', '-')
bug_mining_log = join(log_dir, "bug_mining-{}.log".format(input_file))

# directory tarball explodes into often has version num as part of name
tar_files = sb.check_output(['tar', 'tf', project['tarfile']])
target_name = basename(tar_files.splitlines()[0].rstrip(os.path.sep))

plog = join(project_dir, "queries-{}-{}.iso.plog".format(
    target_name, basename(project['inputs'][0])))
logp(plog)

# returns when this file exists on this host
def wait_for_file(filename):
    while True:
        if os.path.isfile(filename):
            return
        time.sleep(0.1)

# returns true if pattern is in file else false
def find_in_file(pattern, filename):
    with open(filename) as f:
        outp = f.read()
    res = None
    for line in outp.split('\n'):
        foo = re.search(pattern, line)
        if foo:
            return True
    return res is not None

# returns either None
# or a list of matches
def find_in_file_extract(pattern, filename):
    with open(filename) as f:
        outp = f.read()
    res = None
    for line in outp.split('\n'):
        foo = re.search(pattern, line)
        if foo:
            if res is None:
                res = []
            res.append(foo.groups()[0])
    return res

# check for pattern in hostfile and return true if its there
def check_for(pattern, hostfile):
    return find_in_file(pattern, hostfile)

def wait_for(pattern, hostfile):
    while True:
        if (check_for(pattern, hostfile)):
            return

# extracts last
def extract_float(pattern, hostfile):
    assert (check_for(pattern, hostfile))
    res = find_in_file_extract(pattern, hostfile)
    return float(res[-1])

def extract_int(pattern, hostfile):
    res = find_in_file_extract(pattern, hostfile)
    return int(res[-1])

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

    v1=5
    # stage 1 -- instrument source
    wait_for_file(add_queries_log)
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
    pattern = "add queries complete ([0-9\.]+) seconds"
    wait_for(pattern, add_queries_log)
    ti = extract_float(pattern, add_queries_log)
    # grab some neat stats from logfile too
    pattern = "num taint queries added ([0-9]+)"
    res = find_in_file_extract(pattern, add_queries_log)
    # tally up all the queries
    ntq = 0
    for n in res:
        ntq += int(n)
    pattern = "num atp queries added ([0-9]+)"
    res = find_in_file_extract(pattern, add_queries_log)
    natp = 0
    for n in res:
        natp += int(n)
    mon.addstr(v1, 48,   "taint queries: %d" % ntq)
    mon.addstr(v1+1, 48, "  atp queries: %d" % natp)
    mon.refresh()

    time.sleep(0.1)

    # stage 2 -- make
    wait_for_file(make_log)
    # wait for make to finish
    pattern = "make complete ([0-9\.]+) seconds"
    wait_for(pattern, make_log)

    tm = extract_float(pattern, make_log)

    mon.addstr(v1, 4, "%4.2fs" % (ti+tm))
    mon.refresh()

#    mon.addstr(9, 4, "%4.2fs" % tm)
    mon.refresh()
    time.sleep(0.1)

    # stage 2 -- run instr program & record
    v2=8
    wait_for_file(bug_mining_log)
    mon.addstr(v2,  15,  "2. Record run of")
    mon.addstr(v2+1, 15, "   instrumented program")
    mon.refresh()
    # wait for record to finish
    pattern = "panda record complete ([0-9\.]+) seconds"
    wait_for(pattern, bug_mining_log)
    tr = extract_float(pattern, bug_mining_log)
    mon.addstr(v2, 4, "%4.2fs" % tr)
    mon.refresh()

    # stage 3 -- replay + taint
    v3 = 11
    pattern = "Starting first and only replay"
    wait_for(pattern,bug_mining_log)
    mon.addstr(v3, 15, "3. Replay with taint")
    mon.addstr(v3+1, 15, "   propagation")
    mon.refresh()

    done = False
    while not done:
        done = check_for("taint analysis complete ([0-9\.]+) seconds", bug_mining_log)
        if not done:
            logp("still not done")
        pattern = "([0-9\.]+)\%\) instr"
        if (check_for(pattern, bug_mining_log)):
            perc = extract_float(pattern, bug_mining_log)
            mon.addstr(v3+1, 35, " %4.2f%%" % perc)
            mon.refresh()
        time.sleep(0.11)
    mon.addstr(v3+1, 35, " 100.00%")
    mon.refresh()
    time.sleep(0.11)
    mon.addstr(v3+1, 35, "        ")
    mon.refresh()

    # interestiing stats
    pattern = ":\s*([0-9]+) instrs total"
    wait_for(pattern, bug_mining_log)
    ti = extract_int(pattern, bug_mining_log)
    mon.addstr(v3, 48, "instr: %d" % ti)
    mon.refresh()
    time.sleep(0.11)

    pattern = "taint analysis complete ([0-9\.]+) seconds"
    tt = extract_float(pattern, bug_mining_log)
    mon.addstr(v3, 4, "%4.2fs" % tt)
    mon.refresh()

    # figure out how big plog is
    assert os.path.isfile(plog)
    plogsize = os.stat(plog).st_size
    mon.addstr(v3+1, 48, " plog: %d" % plogsize)
    mon.refresh()

    time.sleep(0.11)

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
    db = LavaDatabase(project)
    while not done:
        pattern = "fib complete ([0-9\.]+) seconds"
        done = check_for(pattern, bug_mining_log)
        num_dua = db.session.query(Dua).count()
        num_atp = db.session.query(AttackPoint).count()
        num_bug = db.session.query(Bug).count()
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

    tf = extract_float(pattern, bug_mining_log)
    mon.addstr(v4, 4, "%4.2fs" % tf)
    mon.refresh()

    # stage 5 inj
    v5=20
    for trial in range(1, 4):
        # inject trial $trial
        lf = join(log_dir, "inject-{}.log".format(trial))
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
        pattern = "INJECTING BUGS (.*) SOURCE"
        wait_for(pattern, lf)
        mon.addstr(vt, 40, "I")
        mon.refresh()

        logp("compile")
        # compile
        pattern = "ATTEMPTING BUILD (.*) INJECTED BUG"
        wait_for(pattern, lf)
        mon.addstr(vt, 41, "B")
        mon.refresh()

        logp("orig")
        # validate -- does orig input still exit with 0?
        pattern = "buggy program succeeds (.*) original input"
        wait_for(pattern, lf)
        mon.addstr(vt, 42, "O")
        mon.refresh()

        logp("validate")
        # validate bugs
        pattern = "FUZZED INPUTS"
        check_for(pattern, lf)
        wait_for(pattern, lf)
        mon.addstr(vt, 43, "V")
        mon.refresh()

        logp("yield")
        pattern = "yield ([0-9\.]+) \("
        wait_for(pattern, lf)
        y = extract_float(pattern, lf)
        mon.addstr(vt, 40, "yield: %.2f" % y)
        mon.refresh()

        pattern = "inject complete ([0-9\.]+) seconds"
        wait_for(pattern, lf)
        ti = extract_float(pattern, lf)
        mon.addstr(vt, 4, "%.2fs" % ti)
        mon.refresh()

        trial += 1

    last_build = db.session.query(Build).order_by(-Build.id).limit(1).one()
    terminals = []
    src_dir = join(project_dir, 'bugs', '0', target_name)
    install_dir = join(src_dir, 'lava-install')
    for bug in last_build.bugs:
        if db.session.query(Run)\
                .filter(Run.fuzzed == bug)\
                .filter(Run.build == last_build)\
                .filter(Run.exitcode.in_([134, 139, -6, -11]))\
                .count() > 0:
            unfuzzed_input = join(project_dir, 'inputs', basename(project['inputs'][0]))
            suff = get_suffix(unfuzzed_input)
            pref = unfuzzed_input[:-len(suff)] if suff != "" else unfuzzed_input
            fuzzed_input = "{}-fuzzed-{}{}".format(pref, bug.id, suff)
            cmd = project['command'].format(input_file=fuzzed_input, install_dir=install_dir)
            script = "echo RUNNING COMMAND for bug {}:; echo; echo FUZZED INPUT {}; echo; echo -n 'md5sum '; md5sum {}; echo; echo {}; echo; echo; LD_LIBRARY_PATH={} {}; /bin/sleep 1000"\
                .format(bug.id, fuzzed_input, fuzzed_input, cmd, join(install_dir, 'lib'), cmd)
            terminals.append(sb.Popen(
                ['gnome-terminal', '--geometry=60x24', '-x', 'bash', '-c', script]
            ))

    try:
        while True: pass
    except KeyboardInterrupt: pass

    try: sb.check_call(['killall', 'sleep'])
    except Exception: pass

curses.wrapper(monitor_lava)
