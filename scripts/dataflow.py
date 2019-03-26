import cPickle as pickle

from fninstr import Function, Call, FnPtrAssign
from lava import LavaDatabase, CallTrace, Bug


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
    atplist = db.session.query(Bug.atp).filter(Bug.id.in_(bug_list))\
            .filter(Bug.type == Bug.CHAFF_STACK_UNUSED).all()
    for atp in atplist:
        ctlist = self.session.query(CallTrace).filter(CallTrace.id.in_(atp.ctrace)).all()
        likelyroot = None
        for ctid in atp.ctrace.reverse():
            ct = filter(lambda x: x.id == ctid, ctlist)[0]
            fn = ct.caller.split('!')[1]
            if fn in fundefs and fn not in fpas:
                if likelyroot == None:
                    fnend.append(ct.caller)
                else:
                    fndataflow.append(likelyroot)
                likelyroot = ct.caller
            else:
                # Truncate the CallTrace when function pointer call is found
                if not likelyroot:  likelyroot = ct.caller  # Set End-of-dataflow it's fnptr
                break

        assert(likelyroot)
        fnroot.append(likelyroot)

    with open(fnwhitelist, 'w') as fd:
        for fn in fndataflow:
            fd.write("NOFILENAME %s\n", fn)
        for fn in fnroot:
            fd.write("NOFILENAME %s root\n", fn)
        for fn in fnend:
            fd.write("NOFILENAME %s addvar\n", fn)

