#!/usr/bin/env python

import re
import sys

#dwarfdump -dil $PROG

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

def parse_section(fd):
    result = {'.debug_line': [], '.debug_info': []}
    data = fd.read().strip().split('\n')
    for l in data:
        l = l.strip()
        if l.startswith("0x"):
            result['.debug_line'].append(l)
        elif l.startswith("<") and not l.startswith("<pc>"):
            result['.debug_info'].append(l)
    return result

reloc_base = 0
cur_base_addr = 0
line_info = {}
globvar_info = {}

class TypeInfo:
    def __init__(self):
        self.size = 0
        self.children = []
type_info = {}

with open(sys.argv[1], 'r') as fd:
    data = parse_section(fd)
    tag = ".debug_line"
    if tag in data:
        srcname = ""
        for line in data[tag]:
            line = line.strip()
            if line.startswith("0x"):
                addrstr, rest = line.split('[')
                lnostr, info = rest.split(']')
                if "uri:" in info:
                    srcfn = info.split("uri:")[-1].strip()
                assert (srcfn)
                addr = int(addrstr.strip(), 16) + reloc_base
                lno = int(lnostr.strip().split(',')[0])
                if srcfn not in line_info:
                    line_info[srcfn] = {}
                if lno not in line_info[srcfn]:
                    line_info[srcfn] = {lno: [addr, addr]}
                    prevlno = lno-1
                    if prevlno in line_info[srcfn]:
                        line_info[srcfn][prevlno][1] = addr
                else:
                    line_info[srcfn][lno][1] = addr

    tag = ".debug_info"
    if tag in data:
        for line in data[tag]:
            line = line.strip()
            print(line)
            if not line:
                continue
            if not line.startswith('<'):
                continue

            die = line.split(' ')[0].strip()
            res = parse_die(line)
            if "DW_TAG_compile_unit" in line:
                if 'DW_AT_low_pc' in res:
                    cur_base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                continue

            assert (die.startswith('<') and die.endswith('>'))
            lvl, idx, tname = die[1:-1].split('><')
            print(lvl, idx, tname)

            if "DW_TAG_variable" in line:
                assert ('DW_AT_name' in res)
                name = res['DW_AT_name']
                if 'DW_AT_decl_line' in res:
                    lno = int(res['DW_AT_decl_line'], 16)
                    assert ('DW_AT_decl_file' in res)
                    fn = res['DW_AT_decl_file']

            if "DW_TAG_subprogram" in line:
                pass
