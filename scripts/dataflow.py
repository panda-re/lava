import cPickle as pickle

from fninstr import Function, Call, FnPtrAssign
from lava import LavaDatabase, CallTrace, Bug, AttackPoint


def genFnTraceHelper(db, bug_list, fnwhitelist, fnpickle):
    fundefs = {}
    prots = {}
    calls = {}
    fpas = {}
    with open(fnpickle, "r") as f:
        fundefs = pickle.load(f)
        prots = pickle.load(f)
        calls = pickle.load(f)
        fpas = pickle.load(f)

    fndataflow = []
    fnroot = []
    fnend = []

    # Fake dataflow only for Unused Chaff Bugs
    buglist = db.session.query(Bug).filter(Bug.id.in_(bug_list))\
            .filter(Bug.type == Bug.CHAFF_STACK_UNUSED).all()
    for bug in buglist:
        atp = bug.atp
        ctlist = db.session.query(CallTrace).filter(CallTrace.id.in_(atp.ctrace)).all()
        likelyroot = None
        for ctid in atp.ctrace[::-1]:
            ct = filter(lambda x: x.id == ctid, ctlist)[0]
            fn = ct.caller.split('!')[1]
            if fn in fundefs and fn not in fpas:
                if likelyroot == None:
                    fnend.append(fn)
                else:
                    fndataflow.append(likelyroot)
                likelyroot = fn
            else:
                # Truncate the CallTrace when function pointer call is found
                if not likelyroot:  likelyroot = fn  # Set End-of-dataflow it's fnptr
                break

        assert(likelyroot)
        fnroot.append(likelyroot)

    # Fixup dataflow arg list From other callers
    for fn in fndataflow:
        for caller in calls[fn]:
            fnroot.append(caller.containing_function)

    with open(fnwhitelist, 'w') as fd:
        for fn in fndataflow:
            fd.write("NOFILENAME df %s\n" % fn)
        for fn in fnroot:
            fd.write("NOFILENAME root %s\n" % fn)
        for fn in fnend:
            fd.write("NOFILENAME addvar %s\n" % fn)

