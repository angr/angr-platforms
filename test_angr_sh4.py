#!/usr/bin/env python
import logging
import nose
import os
from angr_platforms.sh4 import instrs_sh4, arch_sh4
import angr
import angr.project
from pyvex.lift.util import *
from pyvex.lifting import register
import cle
import IPython
import pyvex

"""
Lifter class for SH4
Note: modified to allow for direct lifting
"""
class LifterSH4(GymratLifter):

	 instrs = [instrs_sh4.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs_sh4.__dict__.keys())]
	 
	 """
	 Reverse the endianness of the input data (SH4 instructions).  Total hack.
	 """
	 def cheese(self, binData):
	 
		binData = [b for b in binData]
									 
		# This skips the last byte if it is unpaired
		for i in range(0, len(binData) - 1, 2):

			binData[i], binData[i+1] = binData[i+1], binData[i]
						
		return ''.join(binData)
	 
	 def __init__(self, arch, startPos, toLift = "", max_bytes = 100000, max_inst = 10000, cheese=False):
		super(LifterSH4, self).__init__(arch, startPos)
		
		if len(toLift) > 0:
		
			if cheese:
				toLift = self.cheese(toLift)
		
			self.max_bytes = max_bytes
			self.max_inst = max_inst 
			self.bytepos = startPos
			self.irsb = pyvex.IRSB(toLift, startPos, arch)
			self.data = self.thedata = toLift
		
def test_hello():
	"""
	End-to-end Hello World path analysis
	:return:
	"""
	1101000100010110
	
	import logging
	logging.getLogger('pyvex.lift.util.lifter_helper').setLevel('DEBUG')
	
	# This would lift a single instruction, as specified
	#l = LifterSH4(arch_sh4.ArchSH4(), 0, "\x69\x62")
	#l = LifterSH4(arch_sh4.ArchSH4(), 0, "\xd1\x16", max_bytes=2)
	
	#l = LifterSH4(arch_sh4.ArchSH4(), 0, "\x2f\x11", cheese=True, max_bytes=2)
	
	


	ld = cle.Loader(str(os.path.join(os.path.dirname(os.path.realpath(__file__)),'./test_programs/sh4/CADET_00001.sh4')))
	# '''ld.main_object.entry or 0x400506'''
	start = 0x4006a4 #0x400430
	
	bytes = ld.memory.read_bytes(start, 0x1000)
	bytes=''.join(bytes)
	
	l = LifterSH4(arch_sh4.ArchSH4(), start, bytes, cheese=True)

	"""l.irsb = pyvex.IRSB('\x63\x68', 0, arch)

	l.data = l.thedata = "\x63\x68"
	l.max_bytes = 100
	l.bytepos = 0
	l.max_inst = 10000000
	"""	
	
	irsb = l.lift()
	#print irsb.statements
	#irsb.pp()
	
	register(LifterSH4, 'sh4')		

	
	
	
	"""
	irsb = pyvex.IRSB(some_text_data, ld.main_object.entry, ld.main_object.arch)
	irsb.pp()
	"""
	
	"""
	hellobf = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), './test_programs/sh4/CADET_00001.sh4'))
	
	#angr.project.register_default_engine(cle.backends.elf.ELF, angr.engines.SimEngineVEX)
	
	p = angr.Project(hellobf, engines_preset = angr.engines.basic_preset.copy())
	entry = p.factory.entry_state()
	smgr = p.factory.simgr(entry)
	
	try:
		irsb = p.factory.block(p.entry).vex
	except Exception as e:
		print(e)
	IPython.embed()
	
	smgr.explore()
	print(smgr.deadended[0].posix.dumps(1))
	nose.tools.assert_equals(smgr.deadended[0].posix.dumps(1), 'Hello World!\n')
	"""
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
	
	logging.basicConfig(level=logging.INFO)
	test_hello()
	#test_1bytecrackme_good()

