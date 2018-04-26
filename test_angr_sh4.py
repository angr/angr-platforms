#!/usr/bin/env python
import logging
import nose
import os
from angr_platforms.sh4 import *
import angr, cle, pyvex
import IPython
from archinfo.arch import Endness

from angr_platforms.sh4.helpers_sh4 import Cond, ConditionChecker
					
		
"""
Test lifting instructions from the start of a binary
Should end after first BB 
"""
def test_lifting(pth, startOverride = False, bytes = 0x1000):	

	ld = cle.Loader(str(os.path.join(os.path.dirname(os.path.realpath(__file__)),pth)))
	start = startOverride if startOverride != False else ld.main_object.entry 
	bytes = ld.memory.read_bytes(start, bytes)
	bytes=''.join(bytes)
	
	l = helpers_sh4.LifterSH4(arch_sh4.ArchSH4(), start, bytes, revBytes=False)
	
	irsb = l.lift()
	irsb.pp()

"""
Lift an arbitrary instruction	
"""
def test_lift_one(instr):	

	l = helpers_sh4.LifterSH4(arch_sh4.ArchSH4(), 0, instr, revBytes=True, max_bytes=2)
	
	irsb = l.lift()
	irsb.pp()	

"""
End-to-end path analysis
"""
def test_angr(pth):
		
	hellosh4 = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), pth))
	
	p = angr.Project(hellosh4, auto_load_libs=True)
	#entry = p.factory.entry_state()
	entry = p.factory.blank_state(addr=0x400436)
	smgr = p.factory.simgr(entry)
	
	try:
		irsb = p.factory.block(p.entry).vex
	except Exception as e:
		print(e)
	
	#4004ce
	
	c = ConditionChecker(smgr)
	c.addCond(0x400c10, Cond('r1', '==', 0x400bac))
	c.addCond(0x400c10, Cond(0x400c2c, '==', 0x400bac))
	c.addCond(0x400c10, Cond('prevPc', '==', 0x400c0e))
	c.addCond(0x400bac, Cond('prevPc', '==', 0x400c12))
	c.addCond(0x400bb4, Cond('r15', '==', 0x7ffeffa8 - 12))
	c.addCond(0x400bb6, Cond('r14', '==', 0x7ffeffa8 - 12))
	c.addCond(0x400bb8, Cond('r8', '==', 0x7ffeff9c))
	c.addCond(0x400bba, Cond('r8', '==', 0x7ffeff9c - 52))
	c.addCond(0x400bbc, Cond('r3', '==', 0x1000))
	c.addCond(0x400bbe, Cond('r2', '==', 0x4347c000))
	c.addCond(0x400bc0, Cond('r1', '==', 0))
	c.addCond(0x400bc2, Cond(0x7ffeff9c + 4, '==', 0))
	c.addCond(0x400bc4, Cond('r1', '==', -1))
	c.addCond(0x400bc6, Cond(0x7ffeff9c, '==', -1))
	c.addCond(0x400bc8, Cond('r7', '==', 50))
	c.addCond(0x400bca, Cond('r6', '==', 3))
	c.addCond(0x400bce, Cond('r5', '==', lambda c: c.s().regs.r3))
	c.addCond(0x400bce, Cond('r5', '==', 0x1000))
	c.addCond(0x400bce, Cond('r4', '==', 0x4347c000))
	c.addCond(0x400bd0, Cond('r1', '==', 0x4003dc))
	c.addCond(0x4003dc, Cond('prevPc', '==', 0x400bd2))
	c.addCond(0x4003de, Cond('r0', '==', 0x41101c))
	c.addCond(0x4003e0, Cond('r0', '==', 0x4003e4))
	c.addCond(0x4003e2, Cond('r1', '==', 0x400350))
	c.addCond(0x4003e4, Cond('prevPc', '==', 0x4003e2))
	c.addCond(0x4003e6, Cond('r0', '==', 0x400350))
	c.addCond(0x4003e8, Cond('r1', '==', 0x30))
	c.addCond(0x400350, Cond('prevPc', '==', 0x4003e4))
	c.addCond(0x400352, Cond('r0', '==', 0x411004))
	c.addCond(0x400354, Cond('r0', '!=', 0))
	c.addCond(0x400354, Cond('r15', '==', 0x7ffeffa8 - 12))
	c.addCond(0x400356, Cond('r15', '==', 0x7ffeffa8 - 16))
	c.addCond(0x400358, Cond('r0', '==', 0x411008))
	c.addCond(0x40035a, Cond('r0', '!=', 0))
	
	
	#c.execute(36)

	# static hooker
	
	# below assuming entry point is at 0x400436
	
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


	
	c.execute(58)
	
	#print(p.factory.block(0x4006d8).vex)
	
	#print(p.factory.block(0x4006d8).vex)
	
	print(c.instrs)

	IPython.embed()

	
	# TODO - why is the cond failing?
	
	#print(c.smgr.one_active.state.memory.load(0x411004, endness=Endness.LE))
	#print(c.smgr.one_active.state.memory.load(0x411008, endness=Endness.LE))

	
	#print(smgr.one_active.state.regs.pc)
	
	#smgr.step(n=4)
	
	#print(smgr.one_active.state.regs.r14)
	#print(smgr.one_active.state.memory.load(0x7ffeffac))
		
	#for i in range(4):
	
	#	smgr.step(n=1)
	#	print(smgr.one_active.state.regs.pc)
		
	#smgr.explore(until=lambda s: s.active[0].addr == 0x400350)
	
	# TODO: step through each instruction and verify that regs have correct values!
	# Known issues: read/write system calls are probably not working
	
	# smgr.explore()
	
	#print(smgr.deadended[0].posix.dumps(1))
	#nose.tools.assert_equals(smgr.deadended[0].posix.dumps(1), 'Hello World!\n')
	
def test_1bytecrackme_good():
	"""
	The world-famous 1-byte crackme (easy version)
	:return:
	"""
	crackme = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), './test_programs/sh4/1bytecrackme-good.sh4'))
	bad_states = lambda state: "-" in state.posix.dumps(1)
	p = angr.Project(crackme)
	entry = p.factory.entry_state(remove_options={angr.options.LAZY_SOLVES})
	smgr = p.factory.simgr(entry)
	smgr.step(until=lambda lsmgr: len(lsmgr.active) == 0)
	smgr.stash(from_stash="deadended", to_stash="bad", filter_func=bad_states)
	nose.tools.assert_equals("\n", smgr.deadended[0].posix.dumps(0))


if __name__ == '__main__':
	
	angr.calling_conventions.register_default_cc('sh4', helpers_sh4.SimCCSH4LinuxSyscall)
	pyvex.lifting.register(helpers_sh4.LifterSH4, 'sh4')
		
	#logging.basicConfig(level=logging.INFO)
	#logging.getLogger('angr').setLevel('DEBUG')
	#logging.getLogger('pyvex').setLevel('DEBUG')
	
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x4003e2, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x400524, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x40055e, 4)
	#test_lifting('./test_programs/sh4/CADET_00001.sh4', 0x400ba0, 4)
	
	
	#test_lift_one("\x2f\x11")
	#test_lift_one("\x2f\x08")

	test_angr('./test_programs/sh4/CADET_00001.sh4')
	#test_1bytecrackme_good()

