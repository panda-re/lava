import sys
import os
import re
from threading import Thread

try:
    from IPython.kernel.zmq.kernelapp import IPKernelApp

    ZMQ = True
except:
    # had trouble finding kernel.zmq.  Try:
    #   $ pip install -U ipython pyzmq
    ZMQ = False
try:
    import gdb
except:
    print("Either your gdb is not > gdb 7")
    print("Or you are trying to run this without gdb")
    print("Exiting . . .")
    sys.exit(1)


def launch_debug_using_ipython():
    # run this from a gdb session in order to create a 
    # ipython session one could connect to for gdb_python symbol
    # symbol support
    import IPython
    if not ZMQ:
        IPython.embed()
    else:
        IPython.embed_kernel()
        """
        After this you will see:
            NOTE: When using the `ipython kernel` entry point, Ctrl-C will not work.

            To exit, you will have to explicitly quit this process, by either
            sending
            "quit" from a client, or using Ctrl-\ in UNIX-like environments.

            To read more about this, see
            https://github.com/ipython/ipython/issues/2049


            To connect another client to this kernel, use:
                    --existing kernel-138767.json
        To connect to this ipython kernel, from another terminal on same machine
        type:
            $ ipython console --existing kernel-138767.json
        Note that the kernel number will change with each run of the debugging
        application
        To exit, type quit in the ipython terminal, which will give you control
        of the gdb session
        """


class Exit_Breakpoint(gdb.Breakpoint):
    def stop(self):
        ret_data = gdb.execute("info arg", to_string=True)
        ret_code = int(ret_data.split(" = ")[1])
        print("Program exited normal with status: {}".format(ret_code))
        gdb.execute("q")


def event_handler(event):
    def handle_sig_event(event):
        if isinstance(event, gdb.SignalEvent):
            if event.stop_signal in ["SIGSEGV", "SIGABRT"]:
                print("Found a SIG {}".format(event.stop_signal))
                # print gdb.execute("p $_siginfo._sifields._sigfault.si_addr",
                #            to_string=True)
                # print gdb.execute("info proc mappings", to_string=True)
                gdb.execute("bt")
                gdb.execute("p/x $eip")
                gdb.execute("q")
            else:
                # print "Instruction Count = {}".format(get_instr_count())
                print("Reached unhandled signal event: {}".format(event.stop_signal))
                print("Exiting . . .")
                gdb.execute("q")

    if isinstance(event, gdb.SignalEvent):
        handle_sig_event(event)
    # assume we get here from beginning of rr thread stop point
    elif isinstance(event, gdb.StopEvent):
        print("Reached unhandled stop event: {}".format(event))
        print("Exiting . . .")
        gdb.execute("q")


gdb.execute("set breakpoint pending on", to_string=True)
gdb.execute("set pagination off", to_string=True)
gdb.execute("set confirm off", to_string=True)
gdb.execute("set width 0", to_string=True)
gdb.execute("set height 0", to_string=True)
# maybe this will redirect program output to dev/null
gdb.execute("tty /dev/null", to_string=True)

# gdb.execute("break " + atp_loc, to_string=True)
# ATP_Breakpoint(atp_loc)
# set breakpoints on normal exit of program and SEGFAULTS
EXIT_LOC = "exit"
Exit_Breakpoint(EXIT_LOC)
# ensures all signals stop the program
gdb.execute("handle all stop", to_string=True)

# establish callback on stop events
gdb.events.stop.connect(event_handler)

gdb.execute("r")
