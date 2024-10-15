# Input is a bug mining log file.  We will determine total # of instr
# and proceed to normalize every rdf report in the log by dividing by

import sys
import re

bml = sys.argv[1]

with open(bml) as f:
    for line in f:
        foo = re.search("total_instr in replay:\s*([0-9]+)", line)
        if foo:
            total_instr = int(foo.groups()[0])
        foo = re.search("i1=([0-9]+) i2=([0-9]+) rdf_frac=", line)
        if foo:
            i1 = float(int(foo.groups()[0])) / total_instr
            i2 = float(int(foo.groups()[1])) / total_instr
            print("%.4f %.4f %.4f" % (i1, i2, i1 / i2))
