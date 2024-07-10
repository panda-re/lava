import sys
import subprocess as sp
import sys
from pandare.plog_reader import PLogReader

#
# manual_lava.py
# 
# This script gives you enough information to be able to inject bugs by
# hand into a program by telling you when parts of the input are 
# available (pointed to by a local variable) and dead (not used in lots 
# of branches previously).
#
# This may sound familiar, as it is plot of the following novel:
#
# https://ieeexplore.ieee.org/document/7546498 
#
# Given a pandalog generated via a cmdline like the one reproduced below, 
# this script will consider each tainted instruction logged, and if it deems 
# the bytes involved to be (mostly) a copy of input bytes it will print out a 
# message indicating the program or library source line dealing with the 
# copied data (uses the output of PANDA's loaded_libs + addr2line to achieve
# this). The script also reports how many prior branches the input bytes 
# involved have been used to decide. Input bytes used in lots of branches may
# be harder to use to create bugs, you see.  
#
# So, given the script output, you can just pop open the program or library 
# source and start figuring out how to create a bug using and triggered by the
# input bytes.
#
# NB: The script uses the taint compute number to decide if data is probably a 
# copy of input bytes. The max TCN considered a copy is a parameter of this 
# script.
# 
# For this script to work, We need a pandalog with output from *all* of the
# following plugins
#
# loaded_libs     to get modules / base addr 
# tainted_instr   to know what instructions are tainted
# tainted_branch  to determine how 'live' an input byte is
#
# Note, something needs to be labeled as tainted. This might be accomplished 
# with Panda's file_taint but you may want to taint something in another manner.
#
# For example, here is a cmdline for a replay of xmllint for x86_64 and a 
# specific Linux OS. This collects the info this script needs and puts it
# in the pandalog
# 
#   ~/git/panda/build/x86_64-softmmu/panda-system-x86_64 -m 1G    -os linux-64-ubuntu:4.15.0-72-generic  -replay ./slash-sci -pandalog sla.plog  -panda file_taint:filename=slashdot.xml,pos=1 -panda tainted_instr -panda loaded_libs -panda tainted_branch
#
# CAVEAT EMPTOR.  In truth, this script *only* works for xmlint/libxml.  
# If you search for those strings in this script it will be clear how 
# to modify for your program.  
#


# the pandalog
plog = sys.argv[1]

# we will consider anything with this tcn or lower to be a copy
max_tcn = int(sys.argv[2])

# this is where the *exact* binaries that were used to create the slash-sci replay are...
libxml = "install/libxml2/.libs/libxml2.so"
xmllint = "install/libxml2/.libs/xmllint"

# NB: You will need to fiddle with this script wherever those two variables are used
# in order to specialize it to your program + libs. Sorry no time to make it great.


# first go through plog to get a reasonable mapping
libs_for_thread = {}
with PLogReader(plog) as plr:
    for i, m in enumerate(plr):
        if m.HasField("asid_libraries"):
            al = m.asid_libraries
            thread = m.asid  # (al.tid, al.create_time)
            these_libs = []
            for lib in al.modules:
                if "xml" in lib.name:
                    these_libs.append(lib)
            if len(these_libs) > 0:
                if not (thread in libs_for_thread):
                    libs_for_thread[thread] = []
                libs_for_thread[thread].append(these_libs)

threads = list(libs_for_thread.keys())
# ok this is also WRONG.
# it is assuming the 1st thread is the one you care about (which might be true if you scissored carefully)
thread = threads[0]
n = int(len(libs_for_thread[thread]) / 2)
libs = libs_for_thread[thread][n]

tls = {}


def update_tls(tq):
    if tq.HasField("unique_label_set"):
        uls = tq.unique_label_set
        tls[uls.ptr] = set([])
        for l in uls.label:
            tls[uls.ptr].add(l)


def get_module_offset(pc):
    for lib in libs:
        if pc >= lib.base_addr and pc < (lib.base_addr + lib.size):
            return lib.name, pc - lib.base_addr
    return None


# this is the only place where there's xmllint specific mumbo jumbo
def get_src_line(pc):
    foo = get_module_offset(pc)
    if foo:
        (module_name, module_offset) = foo
        if "xmllint" in module_name:
            outp = sp.check_output(("addr2line -e %s 0x%x" % (xmllint, module_offset)).split())
        if "libxml" in module_name:
            outp = sp.check_output(("addr2line -e %s 0x%x" % (libxml, module_offset)).split())
        if not (outp == "??:0"):
            return outp.decode().rstrip()
    return None


def get_fn_offset(a2s, mod_offs):
    last_possible = None
    for (offs, fn_name) in a2s:
        if mod_offs > offs:
            last_possible = (fn_name, mod_offs - offs)
        else:
            break
    return last_possible


tis = set([])
last = None

num_opportunities = 0
label_liveness = {}
with PLogReader(sys.argv[1]) as plr:
    for i, m in enumerate(plr):
        if m.HasField("tainted_branch"):
            tb = m.tainted_branch
            for tq in tb.taint_query:
                for l in tls[tq.ptr]:
                    if not (l in label_liveness):
                        label_liveness[l] = 0
                    label_liveness[l] += 1
        if m.HasField("tainted_instr"):
            ti = m.tainted_instr
            num_copies = 0
            labels = set([])
            for tq in ti.taint_query:
                update_tls(tq)
                for l in tls[tq.ptr]:
                    labels.add(l)
                if tq.tcn <= max_tcn:
                    num_copies += 1
            if num_copies >= 1 and (len(labels)) >= 2:
                outp = get_src_line(m.pc)
                if outp:
                    num_opportunities += 1
                    outp += " -- copy %d bytes" % num_copies
                    outp += " -- labels [" + (str(labels)) + "]"
                    ml = 0
                    for l in labels:
                        ml = max(ml, label_liveness[l])
                    outp += " -- ml=%d" % ml
                    print("trace: instr=%d pc=%x -- %s" % (m.instr, m.pc, outp))
                    last = outp

print("total of %d injection opportunities" % num_opportunities)
