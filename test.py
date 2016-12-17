import angr
import claripy

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

def setup():
	load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}
	p = angr.Project('econotag.bin',load_options=load_options)
	state = p.factory.blank_state()
	load_vector_table(state)
	import IPython; IPython.embed()

def main():
	setup()
main()