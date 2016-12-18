import angr
import claripy
from simuvex import o
import simuvex
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

def p_disas(s,mode,nbef=0,naft=0):
    insts = disas(s,mode,nbef,naft)
    i = 0
    for i in range(nbef):
        print(insts[i])
    if i == 0:
        i = -1
    print(">>> "+insts[i+1])
    for j in range(i+2,len(insts)):
        print(insts[j])

def disas(s,mode,nbef=0,naft=0):
    insts = []
    pc = s.se.any_int(s.ip)
    cap = None
    offset = None
    if mode == "arm":
        cap = cs
        offset = 4
    elif mode == "thumb":
        cap = cst
        offset = 2
        pc = pc - 1
    else:
        raise ValueError("Bad mode!")
    for i in range(1,nbef+1):
        tmp_pc = pc - (offset*i)
        data = s.se.any_str(s.memory.load(tmp_pc,offset))
        i = list(cap.disasm(data,tmp_pc))[0]
        insts.append(str(hex(tmp_pc))+":  "+i.mnemonic + "  " + i.op_str)
    insts.reverse()
    data = s.se.any_str(s.memory.load(pc,offset))
    i = list(cap.disasm(data,pc))[0]
    insts.append(str(hex(pc))+":  "+i.mnemonic + "  " + i.op_str)
    for i in range(1,naft+1):
        tmp_pc = pc + (offset*i)
        data = s.se.any_str(s.memory.load(tmp_pc,offset))
        try:
            i = list(cap.disasm(data,tmp_pc))[0]
        except:
            import IPython; IPython.embed(); import sys; sys.exit()
        insts.append(str(hex(tmp_pc))+":  "+i.mnemonic + "  " + i.op_str)
    return insts

def load_vector_table(state):
    vector_table = [
        0x0001001d,0x00003275,0x0001001d,0x00003f35,
        0x0001001d,0x0001001d,0x0001001d,0x004029d1,
        0x0001001d,0x0001001d,0x0001001d
    ]
    # for i in range(len(vector_table)):
    #     vector_table[i] = vector_table[i] - 1
    start_addr = 0x00400120
    for entry in vector_table:
        c_rep = claripy.BVV(entry,32)
        state.memory.store(start_addr,c_rep,endness='Iend_LE')
        start_addr += 0x4

# def explore_condition(path):
#     return (0x400120 <= path.addr <= (0x400120+0xb*4))

def explore(p,state):
    path = p.factory.path(state)
    pg = p.factory.path_group(path)
    # import IPython; IPython.embed(); import sys; sys.exit()
    # try:
    #     pg.explore(find=0x1082c)
    #     import IPython; IPython.embed(); import sys; sys.exit()
    # except:
    #     import IPython; IPython.embed()
    pg.explore(find=0x1082c)
    # import IPython; IPython.embed(); import sys; sys.exit()
    path = pg.found[0]
    successors = path.step(num_inst=2)
    path = successors[0]
    r0 = path.state.regs.r0
    # import IPython; IPython.embed(); import sys; sys.exit()
    path.state.se.add(r0 < 0xb)
    # r0[hex(path.addr)] = copy.deepcopy(r0['curr'])
    successors = path.step()
    mapping = {}
    for child in successors:
        while (satisfiable(child.state,r0)):
            handler_addr = hex(child.addr)
            inter_num = int(child.state.se.any_int(r0))
            if handler_addr not in mapping:
                mapping[handler_addr] = []
            mapping[handler_addr].append(inter_num)
            child.state.se.add(r0 != inter_num)

    return mapping

def satisfiable(state,value):
    try:
        state.se.any_int(value)
    except simuvex.SimUnsatError:
        return False
    return True

def setup():
    load_options = {'main_opts': {'backend': 'blob', 'custom_arch': 'arm'}}
    p = angr.Project('econotag.bin',load_options=load_options)
    state = p.factory.blank_state(
        add_options={o.BYPASS_UNSUPPORTED_IRCCALL},
        remove_options={o.LAZY_SOLVES},
        addr=0x10810
        )
    load_vector_table(state)
    for addr in msr_mrs:
        p.hook(addr, cpsr_hook, length=4)
    mapping = explore(p,state)
    # import IPython; IPython.embed(); import sys; sys.exit()
    print("Found the following interupt number and handler mappings:\n")
    for key in mapping:
        print("%s: %s" % (key,", ".join([str(x) for x in mapping[key]])))
def main():
    setup()
main()