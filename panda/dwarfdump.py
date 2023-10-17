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
            # Signal End of Text
            if 'ET' in l.split():
                result['.debug_line'].append(None)
        elif l.startswith("<") and not l.startswith("<pc>"):
            result['.debug_info'].append(l)
    return result

reloc_base = 0
line_info = {}
globvar_info = {}
func_info = {}
type_info = {}

class VarInfo:
    def __init__(self, name):
        self.name = name
        self.scope = None
        self.decl_lno = None
        self.decl_fn = None
        self.loc_op = None
        self.type = None

class FuncInfo:
    def __init__(self, cu_off, name, scope, fb_op):
        self.cu_offset = cu_off
        self.name = name
        self.scope = scope
        self.framebase = fb_op
        self.fn = None
        self.lno = None
        self.varlist = []

class TypeInfo:
    def __init__(self):
        self.size = 0
        self.children = []

class Scope:
    def __init__(self, lopc, hipc):
        self.lowpc = lopc
        self.highpc = hipc

with open(sys.argv[1], 'r') as fd:
    data = parse_section(fd)
    tag = ".debug_line"
    if tag in data:
        srcname = ""
        for line in data[tag]:
            if line == None:
                srcname = ""
                continue
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
                    line_info[srcfn][lno] = [Scope(addr, addr), None]
                    prevlno = lno-1
                    while prevlno > 0 and prevlno not in line_info[srcfn]:
                        prevlno -= 1
                    if prevlno != 0 and prevlno in line_info[srcfn]:
                        line_info[srcfn][prevlno][0].highpc = addr
                else:
                    line_info[srcfn][lno][0].highpc = addr

    cu_off = None
    lvl_stack = []
    scope_stack = []
    func_stack = []
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
            assert (die.startswith('<') and die.endswith('>'))
            lvl, idx, tname = die[1:-1].split('><')

            res = parse_die(line)
            if "DW_TAG_compile_unit" in line:
                assert ('DW_AT_low_pc' in res)
                assert ('DW_AT_high_pc' in res)
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope_stack = [Scope(base_addr, end_addr)]
                lvl_stack = [(lvl, 'DW_TAG_compile_unit')]
                func_stack = []
                cu_off = int(idx.split('+')[0], 16)
                continue

            #print(lvl, idx, tname)

            while lvl < lvl_stack[-1][0]:
                lvl_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_lexical_block':
                    scope_stack.pop()
                if lvl_stack[-1][1] == 'DW_TAG_subprogram':
                    func_stack.pop()

            if lvl != lvl_stack[-1][0] or lvl != (lvl_stack[-1][0]+1):
                continue

            if tname == "DW_TAG_lexical_block":
                assert ('DW_AT_low_pc' in res)
                assert ('DW_AT_high_pc' in res)
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope_stack.append(Scope(base_addr, end_addr))
                lvl_stack.append((lvl, 'DW_TAG_lexical_block'))

            elif tname == "DW_TAG_variable":
                assert ('DW_AT_name' in res)
                name = res['DW_AT_name']
                v = VarInfo(name)

                v.scope = scope_stack[-1]
                assert ('DW_AT_decl_line' in res)
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert ('DW_AT_decl_file' in res)
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ')+1:]
                if 'DW_AT_location' not in res:
                    continue
                v.loc_op = res['DW_AT_location'].split(':')[-1].strip()
                assert ('DW_AT_type' in res)
                v.type = int(res['DW_AT_type'], 16)

                if len(func_stack) == 0:
                    if cu_off not in globvar_info:
                        globvar_info[cu_off] = set()
                    globvar_info[cu_off].add(v)
                else:
                    func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_formal_parameter":
                assert ('DW_AT_name' in res)
                name = res['DW_AT_name']
                v = VarInfo(name)

                v.scope = scope_stack[-1]
                assert ('DW_AT_decl_line' in res)
                v.decl_lno = int(res['DW_AT_decl_line'], 16)
                assert ('DW_AT_decl_file' in res)
                v.decl_fn = res['DW_AT_decl_file']
                v.decl_fn = v.decl_fn[v.decl_fn.find(' ')+1:]
                if 'DW_AT_location' not in res:
                    continue
                v.loc_op = res['DW_AT_location'].split(':')[-1].strip()
                assert ('DW_AT_type' in res)
                v.type = int(res['DW_AT_type'], 16)

                assert (len(func_stack) > 0)
                func_stack[-1].varlist.append(v)

            elif tname == "DW_TAG_subprogram":
                assert ('DW_AT_name' in res)
                name = res['DW_AT_name']

                assert ('DW_AT_low_pc' in res)
                assert ('DW_AT_high_pc' in res)
                base_addr = int(res['DW_AT_low_pc'], 16) + reloc_base
                end_addr = int(res['DW_AT_high_pc'], 16) + reloc_base
                scope = Scope(base_addr, end_addr)
                scope_stack.append(scope)
                lvl_stack.append((lvl, 'DW_TAG_subprogram'))

                assert ('DW_AT_decl_file' in res)
                decl_fn = res['DW_AT_decl_file']
                decl_fn = decl_fn[v.decl_fn.find(' ')+1:]

                if 'DW_AT_frame_base' in res:
                    fb_op = res['DW_AT_frame_base'].split(':')[-1].strip()
                else:
                    fb_op = ""

                f = FuncInfo(cu_off, name, scope, fb_op)

                for srcfn in line_info:
                    for lno in line_info[srcfn]:
                        if line_info[srcfn][lno][0].lowpc == base_addr:
                            f.fn = srcfn
                            f.lno = lno
                        if line_info[srcfn][lno][0].lowpc >= base_addr \
                                and line_info[srcfn][lno][0].highpc < end_addr:
                            line_info[srcfn][lno][1] = f

                func_stack.append(f)
                if cu_off not in func_info:
                    func_info[cu_off] = set()
                func_info[cu_off].add(f)
