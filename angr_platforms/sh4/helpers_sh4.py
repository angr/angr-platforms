from angr.calling_conventions import SimCC, SimRegArg
from arch_sh4 import ArchSH4
import instrs_sh4
import pyvex
from pyvex.lifting.util import *

"""
Work in progress calling convention
"""
class SimCCSH4(SimCC):
	ARG_REGS = [ 'r4', 'r5', 'r6', 'r7' ]
	FP_ARG_REGS = [ 'fr4', 'fr5','fr6','fr7','fr8','fr9','fr10','fr11']
	RETURN_ADDR = SimRegArg('pr', 4)
	RETURN_VAL = SimRegArg('r0', 4)
	ARCH = ArchSH4

"""
Lifter class for SH4
Note: modified to allow for direct lifting
"""
class LifterSH4(GymratLifter):

	 instrs = [instrs_sh4.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs_sh4.__dict__.keys())]
	 
	 """
	 Reverse the endianness of the input data (SH4 instructions).  Total hack.
	 Note: only needed if we are loading manually	
	 """
	 def revBytes(self, binData):
	 
		binData = [b for b in binData]
									 
		# This skips the last byte if it is unpaired
		for i in range(0, len(binData) - 1, 2):

			binData[i], binData[i+1] = binData[i+1], binData[i]
						
		return ''.join(binData)
	 
	 def __init__(self, arch, startPos, toLift = "", max_bytes = 100000, max_inst = 10000, revBytes=False):
		super(LifterSH4, self).__init__(arch, startPos)
		
		if len(toLift) > 0:
		
			if revBytes:
				toLift = self.revBytes(toLift)
		
			self.max_bytes = max_bytes
			self.max_inst = max_inst 
			self.bytepos = startPos
			self.irsb = pyvex.IRSB(toLift, startPos, arch)
			self.data = self.thedata = toLift