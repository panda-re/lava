import capstone

md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
out = []
for c in range(0x100):
    seeill = True
    for nc in range(0x100):
        for inst in md.disasm(bytes([c,nc]), 0):
            if inst.mnemonic:
                seeill = False
                break
    if seeill:
        #print(hex(c))
        out.append(c)

print(out)
