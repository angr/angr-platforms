#!/usr/bin/env python
import logging
import os
from angr_platforms.sh4 import *
import angr, cle, pyvex
import IPython
from archinfo.arch import Endness

from angr_platforms.sh4.helpers_sh4 import Cond, ConditionChecker
			
"""
Test cases for SH4 lifter in angr
Author: bob123456678
"""
			
"""
Test lifting instructions from the start of a binary
Should end after first BB 
"""
def test_lifting(pth, startOverride = False, numBytes = 0x1000):	

	ld = cle.Loader(str(os.path.join(os.path.dirname(os.path.realpath(__file__)),pth)))
	start = startOverride if startOverride != False else ld.main_object.entry 
	bytes = ld.memory.read_bytes(start, numBytes)
	bytes=''.join(bytes)
	
	l = helpers_sh4.LifterSH4(arch_sh4.ArchSH4(), start, bytes, revBytes=False)
		
	l.irsb.pp()

"""
Fully test symbolic execution through angr
"""
def test_angr(pth):
			
	hellosh4 = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), pth))
	
	p = angr.Project(hellosh4, auto_load_libs=True)
	entry = p.factory.entry_state()
	smgr = p.factory.simgr(entry)
	smgr2 = p.factory.simgr(entry)

	# All system calls need to be hooked!
	# (this is specific to cadet0001 / cgc elf)
	# TODO: test on more binaries!
	p.hook(0x40036c, angr.SIM_PROCEDURES['posix']['read']())
	p.hook(0x400350, angr.SIM_PROCEDURES['posix']['read']())
	p.hook(0x4003f8, angr.SIM_PROCEDURES['posix']['write']())
	p.hook(0x4003dc, angr.SIM_PROCEDURES['posix']['mmap']())
	p.hook(0x400414, angr.SIM_PROCEDURES['linux_kernel']['munmap']())
	p.hook(0x400b28, angr.SIM_PROCEDURES['cgc']['random']())
	p.hook(0x400aa0, angr.SIM_PROCEDURES['cgc']['fdwait']())
	p.hook(0x4009c0, angr.SIM_PROCEDURES['cgc']['allocate']())
	p.hook(0x400a58, angr.SIM_PROCEDURES['cgc']['deallocate']())
	p.hook(0x400918, angr.SIM_PROCEDURES['cgc']['transmit']())
	p.hook(0x400890, angr.SIM_PROCEDURES['cgc']['receive']())
	p.hook(0x4009a0, angr.SIM_PROCEDURES['cgc']['_terminate']())

	print("Looking for easter egg...")
	
	smgr.explore(avoid=lambda s: "Yes" in s.posix.dumps(1) or "Nope" in s.posix.dumps(1),find=lambda s: "EASTER" in s.posix.dumps(1))
	
	print("Found easter egg")
	
	print(smgr)
	
	for i in range(len(smgr.found)):
		
		print(smgr.found[i].state.posix.dumps(0)[:-1])
		print(smgr.found[i].state.posix.dumps(1))
		
	print("Looking for palindromes...")
	
	smgr2.explore(avoid=lambda s: "EASTER" in s.posix.dumps(1) or "Nope" in s.posix.dumps(1),find=lambda s: "Yes" in s.posix.dumps(1),num_find=1)

	print("Found palindromes")
	
	print(smgr2)
	
	for i in range(len(smgr2.found)):
		
		print(smgr2.found[i].state.posix.dumps(0)[:-1])
		print(smgr2.found[i].state.posix.dumps(1))
		
	#IPython.embed()
		
"""
Dynamically test our lifter using a condition checker
Run this as a sanity check before starting symbolic exploration
"""
def test_dynamic(pth):
		
	hellosh4 = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), pth))
	
	p = angr.Project(hellosh4, auto_load_libs=True)
	#entry = p.factory.entry_state()
	entry = p.factory.blank_state(addr=0x400436)
	smgr = p.factory.simgr(entry)

	try:
		irsb = p.factory.block(p.entry).vex
	except Exception as e:
		print(e)
		
	# below assuming entry point is at 0x400436
	
	c = ConditionChecker(smgr)
	
	c.addCond(0x400438, Cond('r15', '==', 0x7fff0000 - 4))
	c.addCond(0x40043a, Cond('r14', '==', lambda c: c.s().regs.r15))
	c.addCond(0x40043c, Cond('r1', '==', 0x400c38))
	c.addCond(0x40043e, Cond('r6', '==', 31))
	c.addCond(0x400440, Cond('r5', '==', lambda c: c.s().regs.r1))
	c.addCond(0x400442, Cond('r4', '==', 1))
	c.addCond(0x400444, Cond('r1', '==', 0x04006a4))
	c.addCond(0x400446, Cond('prevPc', '==', 0x400444))
	c.addCond(0x400446, Cond('pr', '==', 0x400444+4))
	c.addCond(0x4006a4, Cond('prevPc', '==', 0x400444+2))
	c.addCond(0x4006aa, Cond('r15', '==', 0x7fff0000 - 16))
	c.addCond(0x4006ac, Cond('r15', '==', 0x7fff0000 - 40))
	c.addCond(0x4006b0, Cond('r14', '==', lambda c: c.s().regs.r15))
	c.addCond(0x4006b0, Cond('r1', '==', lambda c: c.s().regs.r14))
	c.addCond(0x4006b2, Cond('r1', '==', lambda c: c.s().regs.r14 - 40))
	c.addCond(0x4006b4, Cond('r4', '==', lambda c: c.mem(c.reg().r1 + 48)))
	c.addCond(0x4006b6, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006b8, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006ba, Cond('r5', '==', lambda c: c.mem(c.reg().r1 + 44)))
	c.addCond(0x4006bc, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006be, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006c0, Cond('r6', '==', lambda c: c.mem(c.reg().r1 + 40)))
	c.addCond(0x4006c2, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006c4, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006c6, Cond('r2', '==', 0))
	c.addCond(0x4006c8, Cond('r2', '==', lambda c: c.mem(c.reg().r1 + 60)))
	c.addCond(0x4006ca, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006cc, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006ce, Cond('r2', '==', 0))
	c.addCond(0x4006d0, Cond('r2', '==', lambda c: c.mem(c.reg().r1 + 52)))
	c.addCond(0x4006d2, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006d4, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006d6, Cond('r1', '==', lambda c: c.mem(0x7ffeffb0 + 44)))
	c.addCond(0x4006d8, Cond('sr', '& 1', 0))
	c.addCond(0x4006e0, Cond('prevPc', '==', 0x4006d8))
	c.addCond(0x4006e2, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006e4, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006e6, Cond('r1', '==', lambda c: c.mem(c.reg().r14)))
	c.addCond(0x4006e8, Cond('sr', '& 1', 0))	
	c.addCond(0x40075e, Cond('prevPc', '==', 0x4006e8))
	c.addCond(0x400760, Cond('r2', '==', lambda c: c.reg().r14))
	c.addCond(0x400762, Cond('r2', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x400764, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x400766, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x400768, Cond('r2', '==', lambda c: c.mem(c.reg().r14 + 20)))
	c.addCond(0x40076a, Cond('r1', '==', lambda c: c.mem(c.reg().r14)))
	c.addCond(0x40076c, Cond('sr', '& 1', 0))	
	c.addCond(0x4006f0, Cond('prevPc', '==', 0x40076c))
	c.addCond(0x4006f2, Cond('r2', '==', lambda c: c.reg().r14))
	c.addCond(0x4006f4, Cond('r2', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006f6, Cond('r1', '==', lambda c: c.reg().r14))
	c.addCond(0x4006f8, Cond('r1', '==', lambda c: c.reg().r14 - 40))
	c.addCond(0x4006fa, Cond('r2', '==', lambda c: c.mem(c.reg().r14 + 4)))
	c.addCond(0x4006fc, Cond('r1', '==', lambda c: c.mem(c.reg().r14 + 20)))
	c.addCond(0x4006fe, Cond('r2', '==', lambda c: c.reg().r3))
	c.addCond(0x400700, Cond('r3', '==', lambda c: c.reg().r1 + c.reg().r2))
	c.addCond(0x400700, Cond('r2', '!=', lambda c: c.reg().r14))
	c.addCond(0x400702, Cond('r2', '==', lambda c: c.reg().r14))
	c.addCond(0x400704, Cond('r2', '==', lambda c: c.reg().r14 - 40))	
	c.addCond(0x40070e, Cond('r2', '==', lambda c: c.mem(c.reg().r14) - c.mem(c.reg().r14 + 20)))
	c.addCond(0x4003fc, Cond('r0', '==', 0x400400))
	c.addCond(0x400400, Cond('prevPc', '==', 0x4003fe))
	c.addCond(0x400350, Cond('prevPc', '==', lambda c: c.mem(0x411020)))

	c.execute(113)
		
	print("Instructions tested:")
	print(sorted(c.instrs))

	#IPython.embed()

if __name__ == '__main__':
	
	#angr.calling_conventions.register_default_cc('sh4', helpers_sh4.SimCCSH4LinuxSyscall)
	#pyvex.lifting.register(helpers_sh4.LifterSH4, 'sh4')
		
	logging.basicConfig(level=logging.INFO)
	logging.getLogger('angr').setLevel('ERROR')
	logging.getLogger('pyvex').setLevel('ERROR') # DEBUG
	
	test_lifting('./test_programs/sh4/CADET_00001.sh4')
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x4003e2, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x400524, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x40055e, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x400ba0, 4)
	
	test_dynamic('./test_programs/sh4/CADET_00001.sh4')

	test_angr('./test_programs/sh4/CADET_00001.sh4')
