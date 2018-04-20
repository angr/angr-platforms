#!/usr/bin/env python
import logging
import nose
import os
from angr_platforms.sh4 import *
import angr, cle, pyvex
import IPython
		
"""
Test lifting instructions from the start of a binary
Should end after first BB 
"""
def test_lifting(pth):	

	ld = cle.Loader(str(os.path.join(os.path.dirname(os.path.realpath(__file__)),pth)))
	start = ld.main_object.entry 
	bytes = ld.memory.read_bytes(start, 0x1000)
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
	
	p = angr.Project(hellosh4, auto_load_libs=False)
	entry = p.factory.entry_state()
	smgr = p.factory.simgr(entry)
	
	try:
		irsb = p.factory.block(p.entry).vex
	except Exception as e:
		print(e)
	
	IPython.embed()
	
	# TODO: step through each instruction and verify that regs have correct values!
	# Known issues: read/write system calls are probably not working
	
	smgr.explore()
	
	print(smgr.deadended[0].posix.dumps(1))
	nose.tools.assert_equals(smgr.deadended[0].posix.dumps(1), 'Hello World!\n')
	
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
	
	angr.calling_conventions.register_default_cc('sh4', helpers_sh4.SimCCSH4)
	pyvex.lifting.register(helpers_sh4.LifterSH4, 'sh4')
	
	logging.basicConfig(level=logging.INFO)
	logging.getLogger('angr').setLevel('DEBUG')
	logging.getLogger('pyvex').setLevel('DEBUG')
	
	#test_lift_one("\x2f\x11")
	#test_lifting('./test_programs/sh4/CADET_00001.sh4')

	test_angr('./test_programs/sh4/CADET_00001.sh4')
	#test_1bytecrackme_good()

