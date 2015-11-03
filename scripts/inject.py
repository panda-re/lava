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
import lockfile
import signal
import atexit
from os.path import basename, dirname, join, abspath

import signal

from lava import *



project = None
# this is how much code we add to top of any file with main fn in it
NUM_LINES_MAIN_INSTR = 5
debugging = True



# run lavatool on this file to inject any parts of this list of bugs 
# offset will be nonzero if file contains main and therefore
# has already been instrumented with a bunch of defs of lava_get and lava_set and so on
def inject_bugs_into_src(bugs, filename, offset):
    global query_build
    global bugs_build
    global lavatool
    global lavadb
    filename_bug_part = bugs_build + "/" + filename
    buglist = ','.join([str(x[0]) for x in bugs])
    cmd = lava_tool + ' -action=inject -bug-list=\"' + buglist \
        + '\" -lava-db=' + lavadb + ' -p ' + bugs_build \
        + ' -main_instr_correction=' + (str(offset)) \
        + ' ' + filename_bug_part \
        + ' ' + '-project-file=' + project_file
    return run_cmd_nto(cmd, None, None)


# run lavatool on this file and add defns for lava_get and lava_set 
def instrument_main(filename):
    global query_build
    global bugs_build
    global lavatool
    global lavadb
    filename_bug_part = bugs_build + "/" + filename
    cmd = lava_tool + ' -action=main -bug-list=\"\"' \
        + ' -lava-db=' + lavadb + ' -p ' + bugs_build \
        + ' ' + filename_bug_part \
        + ' ' + '-project-file=' + project_file
    run_cmd_nto(cmd, None, None)

def add_build_row(bugs, compile_succ):
    conn = get_conn(project)
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


# here's how to run the built program
def run_prog(install_dir, input_file, timeout):
    cmd = project['command'].format(install_dir=install_dir,input_file=input_file)
    print cmd
    envv = {}
    lib_path = project['library_path'].format(install_dir=install_dir)
    envv["LD_LIBRARY_PATH"] = join(install_dir, lib_path)
    return run_cmd(cmd, install_dir, envv, timeout) # shell=True)

import string

def printable(text):
    import string
    # Get the difference of all ASCII characters from the set of printable characters
    nonprintable = set([chr(i) for i in range(256)]).difference(string.printable)
    return ''.join([ '.' if (c in nonprintable)  else c for c in text])


def add_run_row(build_id, fuzz, exitcode, lines, success):
    lines = lines.translate(None, '\'\"')
    lines = printable(lines[0:1024])
    conn = get_conn(project)
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
    parser.add_argument('-b', '--bugid', action="store", default=-1,
            help = 'Bug id (otherwise, highest scored will be chosen)')
    parser.add_argument('-r', '--randomize', action='store_true', default = False,
            help = 'Choose the next bug randomly rather than by score')
    parser.add_argument('-m', '--many', action="store", default=-1,
            help = 'Inject this many bugs (chosen randomly)')
    args = parser.parse_args()
    project = json.load(args.project)
    project_file = args.project.name

    # Set up our globals now that we have a project

    db_host = project['dbhost']
    db = project['db']
    db_user = "postgres"
    db_password = "postgrespostgres"

    timeout = project['timeout']

    sourcefile = {}
    inputfile = {}
    lval = {}
    atptype = {}

    # This is top-level directory for our LAVA stuff.
    top_dir = join(project['directory'], project['name'])
    lava_dir = dirname(dirname(abspath(sys.argv[0])))
    lava_tool = join(lava_dir, 'src_clang', 'build', 'lavaTool')

    # This should be {{directory}}/{{name}}/bugs
    bugs_top_dir = join(top_dir, 'bugs')
    try:
        os.makedirs(bugs_top_dir)
    except: pass

    # This is where we're going to do our injection. We need to make sure it's
    # not being used by another inject.py.
    bugs_parent = ""
    candidate = 0
    bugs_lock = None
    while bugs_parent == "":
        candidate_path = join(bugs_top_dir, str(candidate))
        lock = lockfile.LockFile(candidate_path)
        try:
            lock.acquire(timeout=-1)
            bugs_parent = join(candidate_path)
            bugs_lock = lock
        except lockfile.AlreadyLocked:
            candidate += 1

    print "Using dir", bugs_parent

    atexit.register(bugs_lock.release)
    for sig in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(sig, lambda s, f: sys.exit(0))

    try:
        os.mkdir(bugs_parent)
    except: pass

    if 'source_root' in project:
        source_root = project['source_root']
    else:
        tar_files = subprocess32.check_output(['tar', 'tf', project['tarfile']], stderr=sys.stderr)
        source_root = tar_files.splitlines()[0].split(os.path.sep)[0]

    queries_build = join(top_dir, source_root)
    bugs_build = join(bugs_parent, source_root)
    bugs_install = join(bugs_build, 'lava-install')
    # Make sure directories and btrace is ready for bug injection.
    def run(args, **kwargs):
        print "run(",
        print args,
        print ")"
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

    lavadb = join(top_dir, 'lavadb')

    main_files = set(project['main_file'])

    if not os.path.exists(join(bugs_build, 'compile_commands.json')):
        run([join(lava_dir, 'btrace', 'sw-btrace-to-compiledb'),
                '/home/moyix/git/llvm/Debug+Asserts/lib/clang/3.6.1/include'])
        # also insert instr for main() fn in all files that need it
        print "Instrumenting main fn by running lavatool on %d files\n" % (len(main_files))
        for f in main_files:
            print "injecting lava_set and lava_get code into [%s]" % f
            instrument_main(f)
            run(['git', 'add', f])
        run(['git', 'add', 'compile_commands.json'])
        run(['git', 'commit', '-m', 'Add compile_commands.json and instrument main.'])
        run(shlex.split(project['make']))
        try:
            run(shlex.split("find .  -name '*.[ch]' -exec git add '{}' \\;"))
        except subprocess32.CalledProcessError:
            pass
        run(['git', 'commit', '-m', 'Add compile_commands.json and instrument main.'])
        if not os.path.exists(bugs_install):
            run(project['install'], shell=True)

        # ugh binutils readelf.c will not be lavaTool-able without
        # bfd.h which gets created by make. 
        run_cmd_nto(project["make"], bugs_build, None)
        run(shlex.split("find .  -name '*.[ch]' -exec git add '{}' \\;"))
        try:
            run(['git', 'commit', '-m', 'Adding any make-generated source files'])
        except subprocess32.CalledProcessError:
            pass


    # Now start picking the bug and injecting
    bugs_to_inject = []
    if args.bugid != -1:
        bug_id = int(args.bugid)
        score = 0
        (dua_id, atp_id) = get_bug(project,bug_id)
        bug = (bug_id, dua_id, atp_id, False)
        bugs_to_inject.append(bug)
    elif args.randomize:
        print "Remaining to inject:", remaining_inj(project)
        print "Using strategy: random"
#        (bug_id, dua_id, atp_id, inj) = next_bug_random(project, True)
        bug = next_bug_random(project, True)
        bugs_to_inject.append(bug)
        next_bug_db = True
        num_bugs_to_inject = 1
    elif args.many:
        num_bugs_to_inject = int(args.many)
        print "Injecting %d bugs" % num_bugs_to_inject
        if False:
            # These 10 inject and 4 of them work
            # bn = [8609, 12095, 12789, 6440, 3200, 8634, 12506, 12047, 13822, 11886]
            bn = [11166,9754,15729,17158,3860,7995,348,12562,5065,9157,17245,6715,5315,14417,7889,4605,8033,14638,13115,4299,15488,17011,15785,9122,7475,24,8649,9024,12130,15011,10545,9874,6860,13066,7831,17391,5149,349,13512,14999,9664,16566,12176,1831,13446,6108,8535,15755,9856,10340,5027,4848,2929,3345,6848,11356,3367,9291,1156,15612,5186,3167,14021,2804,8674,7565,14605,5714,2048,15692,11387,1652,14479,11036,7440,10414,10760,16565,11887,3399,15138,12792,350,10661,14977,11651,7715,15318,8053,17385,15477,3031,14434,7004,7668,16544,12248,14936,4367,9745]
            num_bugs_to_inject = len(bn)
            for bug_id in bn:
                (dua_id, atp_id) = get_bug(project, bug_id)
                bug = (bug_id, dua_id, atp_id, False)   
                bugs_to_inject.append(bug)
        else:
            for i in range(num_bugs_to_inject):
                bug = next_bug_random(project, False)
                bugs_to_inject.append(bug)

        print "bugs to inject: " + (str(bugs_to_inject))
        # NB: We won't be updating db for these bugs
#        next_bug_db = True
    else:
        # NB: dont use! this is broken!
        assert (1==0)
        # no args -- get next bug from postgres
        print "Remaining to inject:", remaining_inj(project)
        print "Using strategy: score"
        (score, bug_id, dua_id, atp_id) = next_bug(project)
        next_bug_db = True

    sourcefile = read_i2s(project, "sourcefile")
    inputfile = read_i2s(project, "inputfile")
    lval = read_i2s(project, "lval")
    atptype = read_i2s(project, "atptype")
    
    # collect set of src files into which we must inject code
    src_files = set([])
    i = 0

    if False: 
        srcloc_dua_siphon = set([])
        srcloc_dua_use = set([])
        new_bugs_to_inject = set([])
        for bug in bugs_to_inject:
             (bug_id, dua_id, atp_id, inj) = bug
             dua = Dua(project, dua_id, sourcefile, inputfile, lval)
             atp = Atp(project, atp_id, sourcefile, inputfile, atptype)         
             ds_sl = (dua.filename, dua.line)
             du_sl = (atp.filename, atp.line)
             if ds_sl in srcloc_dua_use:
                 print "discarding bug %d -- dua siphon at same srcloc as prior dua use" % bug_id
                 continue
             if du_sl in srcloc_dua_siphon:
                 print "discarding bug %d -- dua use at same srcloc as prior dua siphon" % bug_id
                 continue
             srcloc_dua_siphon.add(ds_sl)
             srcloc_dua_use.add(du_sl)
             new_bugs_to_inject.add(bug)

        print "%d bugs left" % (len(new_bugs_to_inject))
        bugs_to_inject = new_bugs_to_inject

    for bug in bugs_to_inject:
         (bug_id, dua_id, atp_id, inj) = bug
         print "------------\n"
         print "SELECTED BUG %d : %s" % (i, str(bug_id))#
 ####        if not args.randomize: print "   score=%d " % score
         print "   (%d,%d)" % (dua_id, atp_id)
         dua = Dua(project, dua_id, sourcefile, inputfile, lval)
         atp = Atp(project, atp_id, sourcefile, inputfile, atptype)         
         print "DUA:"
         print "   " + str(dua)
         print "ATP:"
         print "   " + str(atp)
         print "max_tcn=%d  max_liveness=%d" % (dua.max_liveness, dua.max_tcn)
         src_files.add(dua.filename)
         src_files.add(atp.filename)
         i += 1

    # cleanup
    print "------------\n"
    print "CLEAN UP SRC"
    run_cmd_nto("/usr/bin/git checkout -f", bugs_build, None)

    print "------------\n"
    print "INJECTING BUGS INTO SOURCE"
    print "%d source files: " % (len(src_files))
    print src_files
    for src_file in src_files:        
        print "inserting code into dua file %s" % src_file
        offset = 0
        if src_file in main_files:
            offset = NUM_LINES_MAIN_INSTR
        (exitcode, output) = inject_bugs_into_src(bugs_to_inject, src_file, offset)    
        # note: now that we are inserting many dua / atp bug parts into each source, potentially.
        # which means we can't have simple exitcodes to indicate precisely what happened
        print "exitcode = %d" % exitcode

    # ugh -- with tshark if you *dont* do this, your bug-inj source may not build, sadly
    # it looks like their makefile doesn't understand its own dependencies, in fact
    if ('makeclean' in project) and (project['makeclean']):
        run_cmd_nto("make clean", bugs_build, None)
#        (rv, outp) = run_cmd_nto(project['make'] , bugs_build, None)

        
    # compile
    print "------------\n"
    print "ATTEMPTING BUILD OF INJECTED BUG"
    print "build_dir = " + bugs_build
    (rv, outp) = run_cmd_nto(project['make'], bugs_build, None)
    build = False
    if rv!=0:
        # build failed
        print outp
        print "build failed"    
        sys.exit(1)
    else:
        # build success
        build = True
        print "build succeeded"
        (rv, outp) = run_cmd_nto("make install", bugs_build, None)
        # really how can this fail if build succeeds?
        assert (rv == 0)
        print "make install succeeded"

    # add a row to the build table in the db    
    if next_bug_db:
        bug_id = bugs_to_inject[0][0]
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
            (rv, outp) = run_prog(bugs_install, orig_input, timeout)
            if rv != 0:
                print "***** buggy program fails on original input!"
            print "retval = %d" % rv
            print "output:"
            lines = outp[0] + " ; " + outp[1]
            print lines
            if next_bug_db:
                add_run_row(build_id, False, rv, lines, True)
            print "SUCCESS"
            # second, fuzz it with the magic value
            print "TESTING -- FUZZED INPUTS"
            suff = get_suffix(orig_input)
            pref = orig_input[:-len(suff)] if suff != "" else orig_input
            num_real_bugs = 0
            for bug in bugs_to_inject:
                (bug_id, dua_id, atp_id, inj) = bug
                dua = Dua(project, dua_id, sourcefile, inputfile, lval)                
                fuzzed_input = "{}-fuzzed-{}{}".format(pref, bug_id, suff)
                print "fuzzed = [%s]" % fuzzed_input
                mutfile(orig_input, dua.lval_taint, fuzzed_input, bug_id)
                print "testing with fuzzed input for bug %d" % bug_id
                (rv, outp) = run_prog(bugs_install, fuzzed_input, timeout)
                print "retval = %d" % rv
                print "output:"
                lines = outp[0] + " ; " + outp[1]
                print lines
                if next_bug_db:        
                    add_run_row(build_id, True, rv, lines, True)
                if rv == -11 or rv == -6:
                    num_real_bugs += 1
            f = (float(num_real_bugs)) / (len(bugs_to_inject))
            print "yield %.2f (%d out of %d) real bugs" % (f, num_real_bugs, len(bugs_to_inject))
            print "TESTING COMPLETE"
            # NB: at the end of testing, the fuzzed input is still in place
            # if you want to try it 
        except:
            print "TESTING FAIL"
            if next_bug_db:
                add_run_row(build_id, False, 1, "", True)
            raise



