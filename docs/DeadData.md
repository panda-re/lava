LAVA and Dead Available Uncomplicated Data
==========================================

LAVA aims to create input / src-code patch pairs.
If one re-compiles with the patch and then runs the program on the input,
some bug will manifest itself. 


What is dead data and why do we care about it?
----------------------------------------------

In order to insert bugs in programs that are triggered by concrete inputs
we first need to find parts of those inputs that the program is
insensitive to.
That is, we need byte ranges that, if we fuzz them, the program doesn't seem to
care.

Why do we need to identify this "dead" data? 
If we are inserting bugs, we need those to be both *triggerable* and *controllable* 
from the input.
A fairly safe way to do this is to identify parts of the input that the program
doesn't seem to care about, and hijack those to both signal that the bug should
activate and also to provide a knob that controls the bug.

To be more concrete, let's say we identify two 4-byte extents in a input to a program
that are dead.
This means we can fuzz those bytes as much as we want and the program will still
seem to process the input normally.
Note that a better operational definition of the program "not caring" about these 
bytes might be that it follows the same trace regardless of those values. 

Call the two extents of dead data E1 and E2.
Now, let's say there is a statement or function call that we really want to control in 
the program, like a call to memcpy.

    memcpy(d, s, n);

The memcpy is what we want to attack, and we'll call it A.
If we had control of d, s, or n, we have a bug. 

If we know that E1 and E2 are dead and available at temporal points T1 and T2 in 
the run of the program.
If A is encountered at temporal point T3, with T3 > T1 and T3 > T2, 
then we can *create* a bug by introducing dataflow between E1, E2, and A.
We can modify the call to memcpy to have a triggerable and controllable bug in the following
manner

    memcpy(d, s, n + (E1 == 0xdeadbeef) * E2);

If trigger value E1 is magic value 0xdeadbeef, then control value E2 gets added to n and we 
can make this memcpy an overflow at will by fiddling with dead data.


How to find dead data 
---------------------

PANDA's taint system lets us discover E1 and E2 as well as other E.

Using the `file_taint` plugin, we can apply taint labels to reads from a file with a 
particular name under Linux.
Using the `dead_data` plugin, we can compute a measure of how much each byte in an input controls
the program.
Roughly, this is a count of the number of branches that byte was used to decide.

Ok, let's say you have some program and specific input and you want to use PANDA to tell you 
what bytes of that input are "dead".
    

First, create a recording in which you process that input with the program.
Let's assume that replay is in ~/lava/replays/thisreplay-*

Run that replay under PANDA with the following commandline (assuming 32-bit x86).

    ./i386-softmmu/qemu-system-i386 \
    -replay ~/lava/replays/thisreplay \
    -panda 'taint2:no_tp;file_taint:filename=malware.pcap,pos,notaint'

This runs the replay with the file_taint plugin but never actually taints anything.
We are doing this because we don't know how the filename will present
itself to the open system call. 
[Why are we doing `no_tp` thus turning off tainted pointers?]

You should now examine the output of this replay looking for the open of the file you used as 
input in the recording.
You should also determine the last instruction count *before* that open.

For example, given the following replay output

     tshark-nnr:   627640525 ( 67.03%) instrs.   25.14 sec.  0.18 GB ram.                     
     tshark-nnr:   637029006 ( 68.03%) instrs.   25.53 sec.  0.19 GB ram.                     
     saw open of [/home/qemu/.wireshark/hosts]                                                
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/share/wireshark/hosts]            
     saw open of [/etc/resolv.conf]                                                           
     saw open of [/etc/nsswitch.conf]                                                         
     saw open of [/dev/urandom]                                                               
     saw open of [/etc/resolv.conf]                                                           
     saw open of [/etc/nsswitch.conf]                                                         
     saw open of [/dev/urandom]                                                               
     saw open of [/home/qemu/.wireshark/subnets]                                              
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/share/wireshark/subnets]          
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/lib/wireshark/plugins/1.8.2]      
     saw open of [/home/qemu/.wireshark/plugins]                                              
     saw open of [/usr/lib/locale/locale-archive]                                             
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/share/wireshark/preferences]      
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/share/wireshark/wireshark.conf]   
     saw open of [/home/qemu/.wireshark/preferences]                                          
     saw open of [/home/rwhelan/src/wireshark-1.8.2/install/share/wireshark/disabled_protos]  
     saw open of [/home/qemu/.wireshark/disabled_protos]                                      
     saw open of [malware.pcap]                                                               
     saw open of file we want to taint: [malware.pcap]                                        
     saw return from open of [malware.pcap]: asid=0x7ba9000  fd=4                             
     saw read of 4096 bytes in file we want to taint                                          

You would use the following commandline to actually obtain the dead data analysis.

    ./i386-softmmu/qemu-system-i386 \
    -replay  ~/lava/replays/thisreplay \
    -pandalog dd.plog \
    -panda 'taint2:no_tp' \
    -panda 'file_taint:filename=malware.pcap,pos,first_instr=637029006,max_num_labels=5000' \
    -panda dead_data

This will write the dead data analysis to `dd.plog`.
The `first_instr` arg to `file_taint` is speeding things up by only turning on the taint system
right before the open. 
The `max_num_labels` arg to taint2 means we only label the first 5000 bytes of the file.
Another speedup -- you may or may not want to do that.

The dead data pandalog can be read by pandalog_reader in `git/panda/qemu/panda`.
However, we are more likely to consume it along with another analysis.
Keep reading.


Dead, uncomplicated, and available data
----------------------------------------

Dead data is only part of the story.
Once we know that E1 and E2 are dead, we next, logically, want to know where in the program 
they are actually available.
We also want a measure of how complicated a function of the input said available data is.
It won't be much use to us to have access to dead data if we can't easily reason about
the form in which it makes itself available deep in a program.

We use taint compute numbers to determine availability and complexity.
When the taint system encounters a computation like `a=b+c`, if `b` and `c` are both tainted
and have different label sets associated with them, then `a` gets the union of those sets, 
but we also associate with each value a taint compute number *tcn* that measures how far, 
computationally, the value is from inputs.
Values that are direct copies of inputs have tcn=0.
The derived value `a` will get a tcn of `1+max(tcn(b),tcn(c))`.

We determine availability and tcn, again, through the taint system, using queries added to the 
source code via src-to-src transformation with a Clang plugin.
The queries know what source file and line number, and even the name of the quantity queried.
A typical such query looks like this and it operates on an extent:
 
    static void foo(int x) {
        vm_lava_query_buffer(&(x), sizeof(x), "bar.c", "x", 73);

If the instrumented program is compiled and run under PANDA replay this fn will execute a magic
asm instruction that will make all those arguments available in PANDA, which will proceed to 
query taint on extent `x`.
If it finds taint, PANDA will write to the panda log an entry with the set of taint labels, the tcn, the original data queried, 
and other info including the src information from the query.

Here is what the commandline to execute all those taint queries would look like if that replay from above were on an instrumented program. 

    ./i386-softmmu/qemu-system-i386 \
    -replay  ~/lava/replays/thisreplay \
    -pandalog qu.plog \
    -panda 'taint2:no_tp' \
    -panda 'file_taint:filename=malware.pcap,pos,first_instr=637029006,max_num_labels=5000' 

Only difference is we changed the pandalog file and took away the dead data arg.

Note that it is fine to run the same replay to get dd.plog and qu.plog.
[Also note that, here, we probably actually definitely want no_tp]

Finally, these two pandalogs, `dd.plog` and `qu.plog` can be processed using the little program 
in `git/lava/panda/lava_find_avail_dead_data.c` to hunt for dead, available, and uncomplicated extents.
That program takes a bunch of parameters

* max_liveness - discard any E that contains a byte with an label in its taint label set with liveness greater than this.
* max_tcn - discard any E that has a byte with tcn higher than this.
* max_card - discard any E that has a byte with label set of cardinality greater than this.
* extent_size_min, extent_size_max -- discard any extent of size not in this range.

This program also reads in the original input file so that the original data queried can be
compared with what bytes it apparently derived from. 

Compile that program as indicated in the beginning of the src itself. 

Here is how to run that program with `max_liveness=2`, `max_card=4`, `max_tcn=10`, and looking for extents of 2..4 bytes.

     ./lfadd malware.pcap dd.plog qu.plog  2 4 10 2 4 

Which will produce a bunch of output of the form

 
     Found some dead, uncomplicated data.                                            
       filename=[proto.c] astnodename=[value] linenum=2107 len=4 num_tainted=4 -- 4  
     liveness=[0.00,0.61]  tcn=[0,0]   card=[0,1]                                    
     labels:                                                                         
             456 457 458 459                                                         
     data corresponding to those labels:                                             
             63 82 53 63                                                             
     actual data at query:                                                           
             63 82 53 63                                                             
    
    
     Found some dead, uncomplicated data.                                               
       filename=[proto.c] astnodename=[length] linenum=4135 len=4 num_tainted=4 -- 2    
     liveness=[0.00,1.22]  tcn=[0,4]   card=[0,2]                                       
     labels:                                                                            
             1214 1215                                                                  
     data corresponding to those labels:                                                
             00 00                                                                      
     actual data at query:                                                              
             14 00 00 00                                                                

