#!/usr/bin/env python
import logging
import nose
import os
from angr_platforms.sh4 import *
import angr, cle, pyvex
import IPython
from archinfo.arch import Endness

from angr_platforms.sh4.helpers_sh4 import Condition, ConditionChecker
					
		
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
	entry = p.factory.entry_state()
	smgr = p.factory.simgr(entry)
	
	try:
		irsb = p.factory.block(p.entry).vex
	except Exception as e:
		print(e)
	
	#4004ce
	
	c = ConditionChecker(smgr)
	c.addCondition(0x400c10, Condition('r1', '==', 0x400bac))
	c.addCondition(0x400c10, Condition(0x400c2c, '==', 0x400bac))
	c.addCondition(0x400c10, Condition('prevPc', '==', 0x400c0e))
	c.addCondition(0x400bac, Condition('prevPc', '==', 0x400c12))
	c.addCondition(0x400bb4, Condition('r15', '==', 0x7ffeffa8 - 12))
	c.addCondition(0x400bb6, Condition('r14', '==', 0x7ffeffa8 - 12))
	c.addCondition(0x400bb8, Condition('r8', '==', 0x7ffeff9c))
	c.addCondition(0x400bba, Condition('r8', '==', 0x7ffeff9c - 52))
	c.addCondition(0x400bbc, Condition('r3', '==', 0x1000))
	c.addCondition(0x400bbe, Condition('r2', '==', 0x4347c000))
	c.addCondition(0x400bc0, Condition('r1', '==', 0))
	c.addCondition(0x400bc2, Condition(0x7ffeff9c + 4, '==', 0))
	c.addCondition(0x400bc4, Condition('r1', '==', -1))
	c.addCondition(0x400bc6, Condition(0x7ffeff9c, '==', -1))
	c.addCondition(0x400bc8, Condition('r7', '==', 50))
	c.addCondition(0x400bca, Condition('r6', '==', 3))
	c.addCondition(0x400bce, Condition('r5', '==', lambda c: c.s().regs.r3))
	c.addCondition(0x400bce, Condition('r5', '==', 0x1000))
	c.addCondition(0x400bce, Condition('r4', '==', 0x4347c000))
	c.addCondition(0x400bd0, Condition('r1', '==', 0x4003dc))
	c.addCondition(0x4003dc, Condition('prevPc', '==', 0x400bd2))
	c.addCondition(0x4003de, Condition('r0', '==', 0x41101c))
	c.addCondition(0x4003e0, Condition('r0', '==', 0x4003e4))
	c.addCondition(0x4003e2, Condition('r1', '==', 0x400350))
	c.addCondition(0x4003e4, Condition('prevPc', '==', 0x4003e2))
	c.addCondition(0x4003e6, Condition('r0', '==', 0x400350))
	c.addCondition(0x4003e8, Condition('r1', '==', 0x30))
	c.addCondition(0x400350, Condition('prevPc', '==', 0x4003e4))
	c.addCondition(0x400352, Condition('r0', '==', 0x411004))
	c.addCondition(0x400354, Condition('r0', '!=', 0))
	c.addCondition(0x400354, Condition('r15', '==', 0x7ffeffa8 - 12))
	c.addCondition(0x400356, Condition('r15', '==', 0x7ffeffa8 - 16))
	c.addCondition(0x400358, Condition('r0', '==', 0x411008))
	c.addCondition(0x40035a, Condition('r0', '!=', 0))
	
	# static hooker
	
	c.execute(36)
	
	print(c.smgr.one_active.state.memory.load(0x411004, endness=Endness.LE))
	print(c.smgr.one_active.state.memory.load(0x411008, endness=Endness.LE))

	IPython.embed()
	
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

	test_angr('./test_programs/sh4/CADET_00001.sh4')
	#test_1bytecrackme_good()

