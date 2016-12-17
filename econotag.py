#!/usr/bin/env python

# To see what's going on. May want to disable later.
#import logging
#logging.basicConfig(level=logging.INFO)

import struct
from simuvex import o
import claripy
import angr
import capstone
import sys
import IPython

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cst = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}

CPSR_IRQ_DISABLE = 0x80
CPSR_FIQ_DISABLE = 0x40

# Assume CPSR starts with IRQ/FIQ disabled
# Note: This should not really be a global variable, since that will
# cause it to be shared by all paths. Apparently the "right" way to
# do this is to add a SimStatePlugin to store the CPSR value in the
# state. But this suffices for now since we're just looking for the
# first path that enables interrupts.
cpsr = claripy.BVV(CPSR_IRQ_DISABLE|CPSR_FIQ_DISABLE,32)
def cpsr_hook(s):
    global cpsr
    pc = s.se.any_int(s.ip)
    data = s.se.any_str(s.memory.load(pc,4))
    i = list(cs.disasm(data, pc))[0]
    if i.mnemonic == 'msr':
        cpsr = getattr(s.regs, i.op_str.split()[1])
    elif i.mnemonic == 'mrs':
        setattr(s.regs, i.op_str.split()[0][:-1], cpsr)

def interrupts_enabled(p):
    global cpsr
    s = p.state
    return not (s.se.any_int(cpsr) & (CPSR_IRQ_DISABLE|CPSR_FIQ_DISABLE))

p = angr.Project(sys.argv[1], load_options=load_options)

# Addrs of MSR/MRS instructions, found by doing
# objdump -d firmware | grep -E '(mrs|msr)'
# Angr doesn't handle these so we need to emulate it in python
msr_mrs = [
    0x10780, 0x10790, 0x10798, 0x107a8,
    0x107b4, 0x107c0, 0x107c8, 0x107d8,
    0x107e0, 0x107f0, 0x107f8, 0x10808,
    0x10870, 0x10878, 0x402eac, 0x402ebc,
    0x402ecc, 0x402edc, 0x402eec, 0x402efc,
]

# Hook these with our Python replacement
for addr in msr_mrs:
    p.hook(addr, cpsr_hook, length=4)

# To avoid "Unsupported CCall armg_calculate_flags_nzcv"
# We also disable lazy solves because it seems to trip up
# angr and cause it to never reach our target...
ent = p.factory.entry_state(
        add_options={o.BYPASS_UNSUPPORTED_IRCCALL},
        remove_options={o.LAZY_SOLVES}
)

pg = p.factory.path_group(ent)
try:
    pg.explore(find=interrupts_enabled)
except KeyboardInterrupt:
    IPython.embed()

print pg
for i,p in enumerate(pg.found):
    print "===== Path %d =====" % i
    print "Interrupts enabled:", "Yes" if interrupts_enabled(p) else "No"
    vecs = struct.unpack("<11I", p.state.se.any_str(p.state.memory.load(0x400120, 11*4)))
    print "Discovered interrupt vectors at 0x400120:"
    for ino,v in enumerate(vecs):
        print "%2d %08x" % (ino,v)
