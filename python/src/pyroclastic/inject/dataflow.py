import json
from pyroclastic.utils.database_types import LavaDatabase, CallTrace, Bug, BugKind


def genFnTraceHelper(db: LavaDatabase, bug_list: list[Bug], function_whitelist: str, combined_json: str):
    with open(combined_json, "r") as f:
        raw_data = json.load(f)

    fundefs = raw_data["fundefs"]  # Now a flat list of strings
    fpas = raw_data["fpas"]  # Now a flat list of strings
    calls = raw_data["calls"]  # Now a dict mapping: { "fn_name": ["caller1", "caller2"] }

    function_dataflow = []
    function_root = []
    function_end = []

    # Fake dataflow only for Unused Chaff Bugs
    bug_list = db.session.query(Bug).filter(Bug.id.in_(bug_list)).filter(Bug.type == BugKind.BUG_CHAFF_STACK_UNUSED).all()
    for bug in bug_list:
        atp = bug.atp
        likely_root = None
        for calltrace_id in atp.ctrace[::-1]:
            calltrace: CallTrace = db.session.query(CallTrace).get(calltrace_id)
            if not calltrace:
                continue
            function = calltrace.caller.split('!')[1]
            if function in fundefs and function not in fpas:
                if likely_root is None:
                    function_end.append(function)
                else:
                    function_dataflow.append(likely_root)
                likely_root = function
            else:
                # Truncate the CallTrace when function pointer call is found
                if not likely_root:  
                    likely_root = function  # Set End-of-dataflow it's fnptr
                break

        if likely_root:
            function_root.append(likely_root)
        else:
            function_root.append("main")
            function_end.append("main")

    # Fixup dataflow arg list From other callers
    for function in function_dataflow:
        if function in calls:
            for containing_function in calls[function]:
                function_root.append(containing_function)

    with open(function_whitelist, 'a') as fd:
        for fn in function_dataflow:
            fd.write("NOFILENAME df %s\n" % fn)
        for fn in function_root:
            fd.write("NOFILENAME root %s\n" % fn)
        for fn in function_end:
            fd.write("NOFILENAME addvar %s\n" % fn)


def genStackVarHelper(db: LavaDatabase, bug_list: list[Bug], function_whitelist: str):
    function_list = []

    # append addvar to the functions of stack overflow
    bug_list = db.session.query(Bug).filter(Bug.id.in_(bug_list)).filter(Bug.type == BugKind.BUG_CHAFF_STACK_CONST).all()
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
