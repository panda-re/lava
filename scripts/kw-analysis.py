import os 
import re
import glob
import subprocess

# analyze klocwork results
# to determine if it is ever actually finding any of the LAVA bugs

debug = False


def run_cmd(args, cw_dir):
    if debug:
        if not (cw_dir is None):
            print("cwd " + (str(cw_dir)))
        print("run_cmd " + (str(args)))
    p = subprocess.Popen(args, cwd=cw_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p.communicate()


# top-level directory 
d = "/nas/tleek/lava/klocwork-results"
# directory containing klocwork results
kwd = "%s/kw-results-2015-10-15" % d
# directory containing bug repo
gitdir = "%s/ulrich-file-bugs-repo" % d

# get list of bugs
(output, foo) = run_cmd (['git', 'branch', '-a'], gitdir)
branch_names = output.split()
bugs = []
for branch_name in branch_names:
    foo = re.search("remotes/origin/([0-9]+_.*)$", branch_name)
    if foo:
        bugs.append(foo.groups()[0])

print("found %d bugs in repo" % (len(bugs)))

for bug in bugs:
    print("bug %s: " % bug)
    run_cmd(['git', 'checkout', bug], gitdir)
    # check out that bug and find file / line for lava_get
    srcfiles = glob.glob("%s/src/*.[ch]" % gitdir)
    for srcfile in srcfiles:
        (output, bar) = run_cmd(['grep', '-n', 'lava_get()', srcfile], None)
        if output:
            line = int(output.split(':')[0])
            print("truth: %d: %s" % (line, srcfile))
            (p,fn) = os.path.split(srcfile)
            (out2, bar) = run_cmd(['grep', fn, "%s/bug-%s-kw.out" % (kwd, bug)], kwd)
#            print out2
            correct = False
            for o in out2.split("\n"):
                foo2 = re.search("^[0-9]+ \(Local\) [^:]+:([0-9]+) (.*)$", o)
                if foo2:
                    print("  kw: " + o)
                    kw_line = int(foo2.groups()[0])
                    kw_reason = foo2.groups()[1]
#                    print "kwres: %d: %s" % (kw_line, kw_reason)
                    if line == kw_line:
                        correct = True
                        break
            if correct:
                print("SUCCESS")
            else:
                print("FAILURE")
