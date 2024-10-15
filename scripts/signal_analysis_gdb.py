import sys
import os
import re


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

if not "ATP" in os.environ:
    print(os.environ)
    print("Must define ATP breakpoint locations. Exiting . . .")
    sys.exit(1)
else:
    # define dua and atp break point locations
    # must be in format of gdb break points (ie, file : line, *address, symbol_name)
    atp_loc = os.environ['ATP']

BUG_EFFECT_COUNT = 0
SIG_EVENT_COUNT = None
record_regex = re.compile(".*?Log contains ([0-9]+) instructions\..*",
                          re.MULTILINE)
event_regex = re.compile(".*?Current event: ([0-9]+).*", re.MULTILINE)


def get_instr_count():
    data = gdb.execute("info record", to_string=True)
    m = re.search(record_regex, data)
    if m is None:
        print("coulnd't find instruction count in [info record] command")
        print(data)
    return int(m.groups()[0])


def get_event_count():
    data = gdb.execute("when", to_string=True)
    m = re.search(event_regex, data)
    if m is None:
        print("coulnd't find event count in when command")
        print(data)
        assert 0
    return int(m.groups()[0])


# bp_num is int
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


def get_bp_hits(bp_num):
    data = gdb.execute("info b {}".format(bp_num), to_string=True)
    hit_str = "breakpoint already hit "
    if not hit_str in data:
        return 0
    else:
        return int(data.split(hit_str)[1].split()[0])


EXIT_LOC = "exit"


class ATP_Breakpoint(gdb.Breakpoint):
    def stop(self):
        global SIG_EVENT_COUNT
        # if (gdb.execute("info record", to_string=True) ==
        # "No record target is currently active.\n"):
        # gdb.write("Starting recording process")
        # else:
        # gdb.write("Hit ATP again.  Restarting . . .")
        # gdb.execute("record stop")
        # gdb.execute("record full")
        gdb.execute("when")
        print("!! Hit ATP !!")
        # print "Instruction Count =", SIG_EVENT_COUNT - get_event_count()
        print("Events =", SIG_EVENT_COUNT, get_event_count())
        gdb.execute("q")
        sys.exit(0)


class Exit_Breakpoint(gdb.Breakpoint):
    def stop(self):
        ret_data = gdb.execute("info arg", to_string=True)
        ret_code = int(ret_data.split(" = ")[1])
        print("At program exit normal with status: {}".format(ret_code))
        print("Instruction Count = {}".format(get_instr_count()))
        gdb.execute("when")
        # print "Instruction Count = {}".format(get_instr_count())
        ATP_Breakpoint(atp_loc)
        # gdb.execute("set scheduler-locking on")
        gdb.post_event(lambda s: gdb.execute("reverse-continue"))
        gdb.post_event(lambda s: gdb.execute("reverse-continue"))
        # gdb.execute("set scheduler-locking off")
        # gdb.execute("reverse-continue")
        # gdb.execute("q")
        # sys.exit(1)


# class GdbCommand():
# # def __init__(self, cmd):
# # self.cmd = cmd
# def (self):
# cmd = self.args[0]
# # gdb.execute(self.cmd)
# # gdb.write("GDB MESSAGE")
# print "HERE HERE"
# print "About to execute: [{}]".format(self.cmd)
# gdb.execute(self.cmd)

def event_handler(event):
    def handle_sig_event(event):
        if isinstance(event, gdb.SignalEvent):
            if event.stop_signal in ["SIGSEGV", "SIGABRT"]:
                print("Found a SIG {}".format(event.stop_signal))
                print(gdb.execute("p $_siginfo._sifields._sigfault.si_addr",
                                  to_string=True))
                # print gdb.execute("info proc mappings", to_string=True)
                gdb.execute("when")
                # print "Instruction Count = {}".format(get_instr_count())
                ATP_Breakpoint(atp_loc)

                def print_fn(s):
                    print(s)
                    return True

                # gdb.post_event(lambda s: print_fn("hello") and gdb.execute("reverse-continue"))
                # gdb.post_event(lambda s: print_fn("hello2") and gdb.execute("reverse-continue"))
                # gdb.post_event(lambda s: print_fn("hello2") and gdb.execute("reverse-continue"))
                # gdb.execute("set scheduler-locking on")
                # gdb.post_event(lambda s: gdb.execute("reverse-continue"))
                # gdb.post_event(lambda s: gdb.execute("reverse-continue"))
                # gdb.execute("set scheduler-locking off")
                try:
                    global SIG_EVENT_COUNT
                    if SIG_EVENT_COUNT is None:
                        SIG_EVENT_COUNT = get_event_count()
                        print("SIG_EVENT_COUNT: {}".format(SIG_EVENT_COUNT))
                    gdb.execute("reverse-continue")
                    gdb.execute("reverse-continue")
                except gdb.error:
                    pass
                # gdb.execute("reverse-continue")
                # gdb.execute("q")
                # sys.exit(1)
            else:
                # print "Instruction Count = {}".format(get_instr_count())
                print("Reached unhandled signal event: {}".format(event.stop_signal))
                print("Exiting . . .")
                gdb.execute("q")
                sys.exit(1)

    # generic StopEvent handler.  We will assume that we only get here from gdb
    # def handle_stop_event (event):
    # if isinstance(event, gdb.StopEvent):
    # global BUG_EFFECT_COUNT
    # BUG_EFFECT_COUNT += 1
    # print "HANDLING STOP EVENT: STEP COUNT {}".format(BUG_EFFECT_COUNT)
    # if BUG_EFFECT_COUNT > 100000:
    # print "Instruction Count = {}".format(BUG_EFFECT_COUNT)
    # gdb.execute("q")
    # else:
    # # gdb.post_event(run_gdb_si)
    # print "posting an event a si thread from stop event"
    # run_gdb_si()
    # # thread = Thread(target=run_gdb_si)
    # # thread.start()

    if isinstance(event, gdb.SignalEvent):
        handle_sig_event(event)
    # assume we get here from beginning of rr thread stop point
    elif isinstance(event, gdb.StopEvent):
        gdb.execute("c")
        # pass
        # handle_stop_event(event)


gdb.execute("set breakpoint pending on", to_string=True)
gdb.execute("set pagination off", to_string=True)
# gdb.execute("set logging on", to_string=True)
# gdb.execute("set logging file /nas/ulrich/mygdb.log", to_string=True)
# gdb.execute("set verbose off", to_string=True)
gdb.execute("set confirm off", to_string=True)
gdb.execute("set width 0", to_string=True)
gdb.execute("set height 0", to_string=True)
# maybe this will redirect program output to dev/null
gdb.execute("tty /dev/null", to_string=True)

# gdb.execute("break " + atp_loc, to_string=True)
# ATP_Breakpoint(atp_loc)
# set breakpoints on normal exit of program and SEGFAULTS
Exit_Breakpoint(EXIT_LOC)
# gdb.execute("break " + EXIT_LOC, to_string=True)
# gdb.execute("handle SIGSEGV stop")
gdb.execute("handle all stop", to_string=True)

# establish callback on breakpoints
gdb.events.stop.connect(event_handler)

# uncomment this line of code to trigger an ipython kernel session that you can
# console into.  See launch_debug_using_ipython() for more info
# gdb.execute("c")
# import IPython; IPython.embed_kernel()
# gdb.execute("si")
