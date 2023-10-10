#!/usr/bin/env python

import re
import sys

#dwarfdump -di $PROG

def parse_die(ent):
    result = {}
    for e in ent.split('> ')[1:]:
        while e.endswith('>'):
            e = e[:-1]
        assert (e.startswith('DW_AT_'))
        dat = e.split('<')
        attr = dat[0].strip()
        for v in dat[1:]:
            v = v.strip();
            if v:
                result[attr] = v
    return result

cur_base_addr = 0
with open(sys.argv[1], 'r') as fd:
    data = fd.read().strip().split('\n')
    for line in data:
        line = line.strip()
        if not line:
            continue
        if not line.startswith('<'):
            continue

        res = parse_die(line)
        if "DW_TAG_compile_unit" in line:
            if 'DW_AT_low_pc' in res:
                cur_base_addr = res['DW_AT_low_pc']

        if 'DW_AT_decl_line' in res:
            lno = int(res['DW_AT_decl_line'], 16)
            assert ('DW_AT_decl_file' in res)
            fn = res['DW_AT_decl_file']
