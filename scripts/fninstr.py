import sys
import yaml
import re
import pickle
import argparse

debug = True

# When IGNORE_FN_PTRS is set, we don't inject dataflow as an argument when a
# function pointer is called. This needs to match with the same variable
# in lavaTool/include/MatchFinder.h
# Note, no tests pass if this is true
# TODO: parameterize this
IGNORE_FN_PTRS = False

parser = argparse.ArgumentParser(
    description='Use output of LavaFnTool to figure out which parts of preproc code to instrument')

# TODO use vars.py to figure this out instead of arguments
parser.add_argument('-d', '--dataflow', action="store_true", default=False,
                    help="lava is using dataflow")
parser.add_argument('-i', '--input', action="store", default=None,
                    help="name of input yaml file from LavaFnTool")
parser.add_argument('-o', '--output', action="store", default=None,
                    help="name of output yaml file containing instrumentation decisions")

(args, rest) = parser.parse_known_args()

data_flow = args.dataflow


def parse_fundecl(fd):
    ret_type = fd['ret_type']
    params = fd['params']
    if 'extern' in fd:
        ext = fd['extern']
    else:
        ext = None
    return ext, ret_type, params


def check_start_end(x):
    start = x['start']
    end = x['end']
    f1 = start.split(":")[0]
    f2 = end.split(":")[0]
    assert (f1 == f2)
    return f1, start, end, start == end


class Function:

    def __init__(self, fun):
        (self.filename, self.start, self.end, see) = check_start_end(fun)
        self.name = fun['name']
        (self.extern, self.ret_type, self.params) = parse_fundecl(fun['fundecl'])
        self.hasbody = fun['hasbody']
        if self.hasbody:
            assert (not see)


class FnPtrAssign:

    def __init__(self, fpa):
        (self.filename, self.start, self.end, see) = check_start_end(fpa)
        (self.extern, self.ret_type, self.params) = parse_fundecl(fpa['fundecl'])
        # this is the value being assigned to the fn ptr, i.e., the RHS
        self.name = fpa['name']
        assert (not see)


class Call:

    def __init__(self, call):
        # this is the name of the fn called
        self.name = call['name']
        # and this is what fn the call is in
        self.containing_function = call['containing_function']
        (self.filename, self.start, self.end, see) = check_start_end(call)
        self.fnptr = call['fnptr']
        self.args = call['args']
        self.ret_tyep = call['ret_type']
        assert (not see)


fundefs = {}
prots = {}
calls = {}
fpas = {}


def addtohl(h, k, v):
    if not (k in h):
        h[k] = []
    h[k].append(v)


def merge(v, vors):
    if v is None:
        assert (vors is None)
        return
    if vors is None:
        assert (v is None)
    return vors + v


if True:
    for filename in rest:
        print("FILE [%s] " % filename)
        y = yaml.load(open(filename))
        assert (y is not None), "Missing output file from fninstr"
        for x in y:
            #        print x
            if 'fun' in x:
                fd = Function(x['fun'])
                if fd.start == fd.end:
                    continue
                if fd.hasbody:
                    addtohl(fundefs, fd.name, fd)
                else:
                    addtohl(prots, fd.name, fd)
            elif 'call' in x:
                call = Call(x['call'])
                addtohl(calls, call.name, call)
            elif 'fnPtrAssign' in x:
                fpa = FnPtrAssign(x['fnPtrAssign'])
                addtohl(fpas, fpa.name, fpa)

    f = open("getfns.pickle", "wb")
    pickle.dump(fundefs, f)
    pickle.dump(prots, f)
    pickle.dump(calls, f)
    pickle.dump(fpas, f)
    f.close()
else:
    f = open("getfns.pickle", "rb")
    fundefs = pickle.load(f)
    prots = pickle.load(f)
    calls = pickle.load(f)
    fpas = pickle.load(f)
    f.close()

"""

First analysis.
Determine complete set of named function we have seen.
Four sources of information for this.

1. Function definitions. We know it's a definition if it contains an implementation (body)
2. Function declarations (prototype, with return type, and param types)
3. Function calls.  No fn should be called unless we have a prototype for it?  If we are looking at preprocessed code.

"""

all_fns = set()
fns_passed_as_args = {}
for name in prots.keys():
    all_fns.add(name)
print("%d fn names in prots" % (len(all_fns)))
for name in fundefs.keys():
    all_fns.add(name)
print("%d fn names in prots+fundefs" % (len(all_fns)))
for name in calls.keys():
    all_fns.add(name)
print("%d fn names in prots+fundefs+calls" % (len(all_fns)))
for name in calls.keys():
    # examine args in each of the calls
    # to see if any are passing a function or fn pointer
    for call in calls[name]:
        if not (call.args is None):
            for item in call.args:
                arg = item['arg']
                if not arg: continue
                if arg['info'] == "function" and arg['name'] != "None":
                    all_fns.add(arg['name'])
                    addtohl(fns_passed_as_args, arg['name'], call.name)

print("%d fn names in prots+fundefs+calls+callargs" % (len(all_fns)))

"""

Second analysis.

Determine which functions we will instrument. This is a little more
complicated than determining which are internal functions for which
we have bodies and which are not. When we say we will instrument a
function we mean both of the following.

  * Adding lava queries to body (that could later find DUAs or ATPs
    under taint analysis).
  * If we are using data flow, then it also means adding data_flow
    first arg to defn, prototype, and all calls

When do we instrument a function 'foo'?

1. Obviously, only if 'foo' has an implmentation (body) can it be
   a candidate to be instrumented in the first place.

2. Say a function 'foo' is a candidate for instrumentation. But
   'foo' is passed, as a paramenter, to another function, 'bar'.
   If 'bar' is not a candidate for instrumention then neither can
   'foo' be since calls to 'foo' from bar can't be instrumented.
   Note that resolving this sort of relation requires recursing.

3. If a function's body isnt instrumented then calls to that function
   cannot be instrumnted with data_flow arg.

4. Probably we can safely ignore 'extern' since it is often, oddly,
   applied to functions for which we observe a body.

"""

instr_judgement = {}

# ok to instrument
OKI = 0
# don't instrument body
DIB = 1
# don't add data flow arg
DADFA = 2

for name in all_fns:

    if name in fundefs:
        for fd in fundefs[name]:
            assert fd.hasbody
            instr_judgement[name] = OKI
            if debug:
                print("Instr candidate %s has body" % name)
            break
    else:
        # we have no fundec for this fn, thus definitely no body.
        # so don't instrument
        instr_judgement[name] = DIB | DADFA
        if debug:
            print("Won't instrument %s (data_flow) since we don't have body" % name)

instr = set()
for name in instr_judgement.keys():
    if instr_judgement[name] == 0:
        instr.add(name)

"""
Make another pass to see if there are any fns passed as args to
other fns that are, themselves, not instrumentable.  Which means
they, too, cannot tolerate a change in prototypes (data_flow arg).
"""
for name in instr:
    if name in fns_passed_as_args:
        disposition = OKI
        for called_fn in fns_passed_as_args[name]:
            if not (instr_judgement[called_fn] == OKI):
                disposition |= DADFA
                disposition |= DIB
                break
        # fn is not ok to instrument
        if not (disposition is OKI):
            instr_judgement[name] = disposition

"""
Make another pass to see if there are any fns assigned to fnptrs
If so, (for now) we won't inject in them since we can't control the
type of the function pointer
"""
if IGNORE_FN_PTRS:
    for name in fpas:
        instr_judgement[name] |= DADFA | DIB

# Ok we have a list of instrumentable functions.
# Now, we need to transitively close.
# If fn1 is un-instrumentable, and if contains calls
# to fn2, then fn2 also cannot be instrumented.
any_change = True
while any_change:
    any_change = False
    for called_fn_name in calls.keys():
        if instr_judgement[called_fn_name] is OKI:
            # We 'think' we can instrument called_fn_name
            for call in calls[called_fn_name]:
                if not (instr_judgement[call.containing_function] is OKI):
                    # ... however, it is called from a function that cant be instrumented
                    # thus it cant really be instrumented.
                    any_change = True
                    print("Cant instrument %s because its called from %s which we can't instrument" % (
                    called_fn_name, call.containing_function))
                    instr_judgement[called_fn_name] = DIB | DADFA
                    break
    if any_change:
        print("instr_judgement changed. Iterating.")

ninstr = {}
for name in instr:
    disp = instr_judgement[name]
    if not disp in ninstr:
        ninstr[disp] = 0
    ninstr[disp] += 1

for i in range(4):
    if i in ninstr:
        print("instrflags=%d: count=%d" % (i, ninstr[i]))

for name in instr_judgement.keys():
    if instr_judgement[name] == OKI:
        print("Intrumenting fun [%s]" % name)

f = open(args.output, "w")
for name in instr_judgement.keys():
    if instr_judgement[name] == OKI:
        f.write("NOFILENAME %s\n" % name)
f.close()
