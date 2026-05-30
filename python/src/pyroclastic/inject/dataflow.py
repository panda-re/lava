import cPickle as pickle
from pyroclastic.utils.database_types import LavaDatabase, CallTrace, Bug, BugKind


def genFnTraceHelper(db: LavaDatabase, bug_list: list[Bug], function_whitelist: str, fnpickle):
    fundefs = {}
    calls = {}
    fpas = {}
    with open(fnpickle, "r") as f:
        fundefs = pickle.load(f)
        calls = pickle.load(f)
        fpas = pickle.load(f)

    function_dataflow = []
    function_root = []
    function_end = []

    # Fake dataflow only for Unused Chaff Bugs
    bug_list = db.session.query(Bug).filter(Bug.id.in_(bug_list)).filter(Bug.type == BugKind.BUG_CHAFF_STACK_UNUSED).all()
    for bug in bug_list:
        atp = bug.atp
        calltrace_list = db.session.query(CallTrace).filter(CallTrace.id.in_(atp.ctrace)).all()
        likely_root = None
        for calltrace_id in atp.ctrace[::-1]:
            calltrace = filter(lambda x: x.id == calltrace_id, calltrace_list)[0]
            fn = calltrace.caller.split('!')[1]
            if fn in fundefs and fn not in fpas:
                if likely_root is None:
                    function_end.append(fn)
                else:
                    function_dataflow.append(likely_root)
                likely_root = fn
            else:
                # Truncate the CallTrace when function pointer call is found
                if not likely_root:  
                    likely_root = fn  # Set End-of-dataflow it's fnptr
                break

        if likely_root:
            function_root.append(likely_root)
        else:
            function_root.append("main")
            function_end.append("main")

    # Fixup dataflow arg list From other callers
    for fn in function_dataflow:
        for caller in calls[fn]:
            function_root.append(caller.containing_function)

    with open(function_whitelist, 'w') as fd:
        for fn in function_dataflow:
            fd.write("NOFILENAME df %s\n" % fn)
        for fn in function_root:
            fd.write("NOFILENAME root %s\n" % fn)
        for fn in function_end:
            fd.write("NOFILENAME addvar %s\n" % fn)


def genStackVarHelper(db: LavaDatabase, bug_list: list[Bug], function_whitelist: str):
    function_list = []

    # append addvar to the functions of stack overflow
    bug_list = db.session.query(Bug).filter(Bug.id.in_(bug_list)).filter(Bug.type == Bug.CHAFF_STACK_CONST).all()
    for bug in bug_list:
        atp = bug.atp
        if atp.ctrace:
            current_calltrace_id = atp.ctrace[-1]
            calltrace = db.session.query(CallTrace).get(current_calltrace_id)
            function = calltrace.caller.split('!')[1]
            function_list.append(function)
        else:
            function_list.append("main")

    with open(function_whitelist, 'a') as fd:
        for fn in function_list:
            fd.write("NOFILENAME addvar %s\n" % fn)
