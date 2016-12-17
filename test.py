import angr
import claripy
from simuvex import o
import capstone

cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
cst = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_THUMB)
load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}
msr_mrs = [
    0x10780, 0x10790, 0x10798, 0x107a8,
    0x107b4, 0x107c0, 0x107c8, 0x107d8,
    0x107e0, 0x107f0, 0x107f8, 0x10808,
    0x10870, 0x10878, 0x402eac, 0x402ebc,
    0x402ecc, 0x402edc, 0x402eec, 0x402efc,
]
CPSR_IRQ_DISABLE = 0x80
CPSR_FIQ_DISABLE = 0x40

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

def load_vector_table(state):
	vector_table = [
		0x0001001d,0x00003275,0x0001001d,0x00003f35,
		0x0001001d,0x0001001d,0x0001001d,0x004029d1,
		0x0001001d,0x0001001d,0x0001001d
	]
	start_addr = 0x00400120
	for entry in vector_table:
		c_rep = claripy.BVV(entry,32)
		state.memory.store(start_addr,c_rep,endness='Iend_LE')
		start_addr += 0x4

def explore_condition(path):
	return (0x400120 <= path.addr <= (0x400120+0xb*4))

def explore(p,state):
	path = p.factory.path(state)
	pg = p.factory.path_group(path)
	try:
		pg.explore(find=explore_condition)
	except:
		import IPython; IPython.embed()

def setup():
	load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}
	p = angr.Project('econotag.bin',load_options=load_options)
	state = p.factory.entry_state(
		add_options={o.BYPASS_UNSUPPORTED_IRCCALL},
        remove_options={o.LAZY_SOLVES}
	    )
	load_vector_table(state)
	for addr in msr_mrs:
	    p.hook(addr, cpsr_hook, length=4)
	explore(p,state)

def main():
	setup()
main()