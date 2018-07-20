import sys
import yaml
import re
import cPickle as pickle
import argparse

debug = True


parser = argparse.ArgumentParser(description='Use output of LavaFnTool to figure out which parts of preproc code to instrument')
parser.add_argument('-d', '--dataflow', action="store_true", default=False,
                    help="lava is using dataflow")
parser.add_argument('-i', '--input', action="store", default=None,
                    help="name of input yaml file from LavaFnTool")
parser.add_argument('-o', '--output', action="store", default=None,
                    help="name of output yaml file containing instrumentation decisions")

(args,rest) = parser.parse_known_args()

data_flow = args.dataflow


def parse_fundecl(fd):
    ret_type = fd['ret_type']
    params = fd['params']
    if 'extern' in fd:
        ext = fd['extern']
    else:
        ext = None
    return (ext, ret_type, params)


def check_start_end(x):
    start = x['start']
    end = x['end']
    (f1, a, b) = start.split(":")
    (f2, c, d) = end.split(":")
    assert (f1 == f2)
    return (f1, start, end, start==end)


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
        # this is the value being assigned to the fn ptr, i.e. the RHS
        self.name = fpa['name']
        assert (not see)
        

class Call:

    def __init__(self, call):
        self.name = call['name']
        (self.filename, self.start, self.end, see) = check_start_end(call)
        self.fnptr = call['fnptr']
        self.args = call['args']
        self.ret_tyep = call['ret_type']
        assert (not see)
    

fundefs = {}
prots = {}
calls = {}
fpas = {}

def addtohl(h,k,v):
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
        print "FILE [%s] " % filename
        y = yaml.load(open(filename))
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

    f = open("getfns.pickle", "w")
    pickle.dump(fundefs, f)
    pickle.dump(prots, f)
    pickle.dump(calls, f)
    pickle.dump(fpas, f)
    f.close()
else:
    f = open("getfns.pickle", "r")
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

allfns = set()
fns_passed_as_args = {}
for name in prots.keys():
    allfns.add(name)
print "%d fn names in prots" % (len(allfns))
for name in fundefs.keys():
    allfns.add(name)
print "%d fn names in prots+fundefs" % (len(allfns))
for name in calls.keys():
    allfns.add(name)
print "%d fn names in prots+fundefs+calls" % (len(allfns))
for name in calls.keys():
    # examine args in each of the calls
    # to see if any are passing a function or fn pointer
    for call in calls[name]:
        if not (call.args is None):
            for item in call.args:
                arg = item['arg']
                if arg['info'] == "function" and arg['name'] != "None":
                    allfns.add(arg['name'])
                    addtohl(fns_passed_as_args, arg['name'], call.name)

print "%d fn names in prots+fundefs+calls+callargs" % (len(allfns))                             


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

1. If 'foo' is EVER seen to have storage class 'extern' then we WONT
   instrument it.

2. If 'foo' is NEVER seen to have a body, we won't instrument it. 

3. If 'foo' is passed as an arg to a function 'bar', i.e., 
   bar(..., foo, ...);   

There are four possibilities

  i. bar ext, foo ext: bar & foo can't be instrumented since they are ext.
     Call to bar and prototypes is all we see.
     Dont add data_flow arg.

  ii. bar ext, foo int: bar can't be instr. Foo -- we can't add data_flow
     Arg to its prototype since this fn will be called from outside 
     our code. Should we instrument foo's body?  Well it couldn't use 
     data_flow but it could be intstrumented (to look for DUAs and ATPs) 
     if we aren't using data_flow.  
     This is the qsort(..., my_compare_fn) case by the way.

  iii. bar int, foo ext: fine to instrument bar.  Foo we can't instrument.
     This is the my_fn(qsort) case.

  iv. bar int, foo int: Fine to instrument both.  

So to summarize, if internal function 'bar' is EVER passed to an external fn
that means we can't instrument bar's body or change its args.

4. What if we ever assign a fn pointer to a function?  God knows 
what we do in that case.  We might have the right info in collected
.fn files from LavaFnTool but will figure that out when we have an 
example that requires it.  


"""

instr_fns = {}

# ok to instrument
OKI = 0
# don't instrument body
DIB = 1
# don't add data flow arg
DADFA = 2
for name in allfns:

    instr_fns[name] = OKI
    disposition = OKI

    if name in prots: 
        for prot in prots[name]:
            if prot.extern:
                disposition |= DIB
                disposition |= DADFA
                if debug: print "Won't instrument %s (body or data_flow) since it was def extern" % name
                break

    if disposition is OKI:
        if not (name in fundefs):
            # we have no body for this fn, no definition,
            # thus we shouldn't instrument since it can't be internal
            disposition |= DIB
            disposition |= DADFA
            if debug: print "Won't instrument %s (body or data_flow) since we don't have body" % name
        else:
            for fd in fundefs[name]:
                assert fd.hasbody
                if fd.extern:
                    # fd has body but is also labeled extern?
                    # seems like something we shouldn't instrument
                    disposition |= DIB
                    disposition |= DADFA
                    if debug: print "Won't instrument %s (body or data_flow) even though we have body since it was def extern" % name
                    break

    # fn is not ok to instrument
    if not (disposition is OKI):
        instr_fns[name] = disposition


instr = set()
for name in instr_fns.keys():
    if instr_fns[name] == 0:
        instr.add(name)


# make another pass to see if there are any fn passed as args to other fns 
# that are, themselves, not instrumentable.  which means they, too, cannot 
# tolerate a change in prototypes (data_flow arg).
for name in instr:
    if name in fns_passed_as_args:
        disposition = OKI
        for called_fn in fns_passed_as_args[name]:
            if not (instr_fns[called_fn] == OKI):
                disposition |= DADFA
                if data_flow:
                    # if we are using data flow note that we won't
                    # be able to make use of DUAs / ATPs in this code
                    # so we shouldn't bother instrumenting body either
                    disposition |= DIB
                    print "Won't instrument %s (body or data_flow) bc its passed as a fn to an uninstrumented fn" % name
                else:
                    print "Won't instrument %s (data_flow) bc its passed as a fn to an uninstrumented fn" % name
                break
        # fn is not ok to instrument
        if not (disposition is OKI):
            instr_fns[name] = disposition


ninstr = {}
for name in instr:
    disp = instr_fns[name]
    if not disp in ninstr:
        ninstr[disp] = 0
    ninstr[disp] += 1


for i in range(4):
    if i in ninstr:
        print "instrflags=%d: count=%d" % (i, ninstr[i])

for name in instr_fns.keys():
    if instr_fns[name] == OKI:
        print "Intrumenting fun [%s]" % name
    
    


f = open(args.output, "w")
for name in instr_fns.keys():
    f.write("%s %d\n" % (name, instr_fns[name]))
f.close()




