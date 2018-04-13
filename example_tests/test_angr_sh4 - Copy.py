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


DEFAULT_CC = {
	'AMD64': SimCCSystemVAMD64,
	'X86': SimCCCdecl,
	'ARMEL': SimCCARM,
	'ARMHF': SimCCARM,
	'MIPS32': SimCCO32,
	'MIPS64': SimCCO64,
	'PPC32': SimCCPowerPC,
	'PPC64': SimCCPowerPC64,
	'AARCH64': SimCCAArch64,
	'AVR': SimCCUnknown,
	'MSP': SimCCUnknown,
	'sh4': SimCCUnknown,
	'SH4': SimCCUnknown
}

"""

class LifterSH4(GymratLifter):
	 instrs = [instrs_sh4.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs_sh4.__dict__.keys())]
	 
	 def __init__(self, arch, startPos, toLift = "", max_bytes = 10000000, max_inst = 1000000):
		super(LifterSH4, self).__init__(arch, startPos)
		
		if len(toLift) > 0:
		
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
	import logging
	logging.getLogger('pyvex.lift.util.lifter_helper').setLevel('DEBUG')
	
	register(LifterSH4, 'sh4')		
	 
	l = LifterSH4(arch_sh4.ArchSH4(), 0)
	
	
	"""l.irsb = pyvex.IRSB('\x63\x68', 0, arch)

	l.data = l.thedata = "\x63\x68"
	l.max_bytes = 100
	l.bytepos = 0
	l.max_inst = 10000000
	"""
	
	irsb = l.lift()
	print irsb.statements
	irsb.pp()
	
	"""
	ld = cle.Loader(str(os.path.join(os.path.dirname(os.path.realpath(__file__)),'./test_programs/sh4/CADET_00001.sh4')))
	
	some_text_data = ''.join(ld.memory.read_bytes(ld.main_object.entry, 0x100))
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

