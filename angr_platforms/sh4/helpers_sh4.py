from angr.calling_conventions import SimCC, SimRegArg
from arch_sh4 import ArchSH4
import instrs_sh4
import pyvex
from pyvex.lifting.util import *
import inspect
import angr
from archinfo.arch import Endness

"""
Lifter and other helper classes for angr SH4 support
Author: bob123456678
"""

"""
Work in progress calling convention
"""
class SimCCSH4(SimCC):
	ARG_REGS = [ 'r4', 'r5', 'r6', 'r7' ]
	FP_ARG_REGS = [ 'fr4', 'fr5','fr6','fr7','fr8','fr9','fr10','fr11']
	RETURN_ADDR = SimRegArg('pr', 4)
	RETURN_VAL = SimRegArg('r0', 4)
	ARCH = ArchSH4

class SimCCSH4LinuxSyscall(SimCC):
    # TODO: Make sure all the information is correct
	ARG_REGS = [ 'r4', 'r5', 'r6', 'r7' ]
	FP_ARG_REGS = [ 'fr4', 'fr5','fr6','fr7','fr8','fr9','fr10','fr11']
	RETURN_ADDR = SimRegArg('pr', 4)
	RETURN_VAL = SimRegArg('r0', 4)

	@classmethod
	def _match(cls, arch, args, sp_delta):  # pylint: disable=unused-argument
		# never appears anywhere except syscalls
		return False

	@staticmethod
	def syscall_num(state):
		return state.regs.r0
	
"""
Lifter class for SH4
Note: modified to allow for direct lifting
"""
class LifterSH4(GymratLifter):

	 instrs = [instrs_sh4.__dict__[x] for x in filter(lambda x: x.startswith("Instruction_"), instrs_sh4.__dict__.keys())]
	 
	 """
	 Reverse the order of the input data (SH4 instructions).
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
			
"""
Class representing a condition to check register or memory values
"""
class Cond():

	__slots__ = ('i','checkValue','operation','desiredValue')
	
	def __init__(self, checkValue, operation, desiredValue):
	
		self.operation = operation
		self.checkValue = checkValue
		self.desiredValue = desiredValue
		
	def toString(self, actualValue):
	
		checkValue = self.checkValue
		if isinstance(checkValue, int):
			checkValue = "mem[%s]" % hex(checkValue)
		elif callable(checkValue):
			checkValue = inspect.getsource(checkValue)
	
		if callable(self.desiredValue):
			desiredValue = inspect.getsource(self.desiredValue)
		else:
			desiredValue = hex(self.desiredValue)
	
		return "%s (%s) %s %s" % (checkValue, actualValue, self.operation, desiredValue)
		
"""
Class that runs a binary using a simulation manager while checking conditions on register/mem values
"""
class ConditionChecker():

	smgr = None
	
	# Previous program counter
	prevPc = 0
	
	# Internal list of conditions
	conds = {}
	
	# Mapping from strings to actual objects in smgr
	mapping = None
	
	# Save all lifted instructions
	instrs = set()
	
	# Number of conditions seen so far
	count = 0
	execCount = 0
	
	# Concretizes PC so that it can be read in our dict
	def getPc(self):

		return self.smgr.one_active.state.solver.eval(self.smgr.one_active.regs.pc,cast_to=int)
		
	def __init__(self, initState):
	
		self.smgr = initState
		self.prevPc = 0
				
		self.mapping = {
			'r15' : lambda : self.smgr.one_active.state.regs.r15,
			'r14' : lambda : self.smgr.one_active.state.regs.r14,
			'r13' : lambda : self.smgr.one_active.state.regs.r13,
			'r12' : lambda : self.smgr.one_active.state.regs.r12,
			'r11' : lambda : self.smgr.one_active.state.regs.r11,
			'r10' : lambda : self.smgr.one_active.state.regs.r10,
			'r9'  : lambda : self.smgr.one_active.state.regs.r9,
			'r8'  : lambda : self.smgr.one_active.state.regs.r8,
			'r7'  : lambda : self.smgr.one_active.state.regs.r7,
			'r6'  : lambda : self.smgr.one_active.state.regs.r6,
			'r5'  : lambda : self.smgr.one_active.state.regs.r5,
			'r4'  : lambda : self.smgr.one_active.state.regs.r4,
			'r3'  : lambda : self.smgr.one_active.state.regs.r3,
			'r2'  : lambda : self.smgr.one_active.state.regs.r2,
			'r1'  : lambda : self.smgr.one_active.state.regs.r1,
			'r0'  : lambda : self.smgr.one_active.state.regs.r0,
			'pc'  : lambda : self.smgr.one_active.state.regs.pc,
			'pr'  : lambda : self.smgr.one_active.state.regs.pr,
			'sr'  : lambda : self.smgr.one_active.state.regs.sr,
			'fpul'  : lambda : self.smgr.one_active.state.regs.fpul
		}
	
	"""
	Shorthand for getting state
	"""
	def s(self):
	
		return self.smgr.one_active.state
	
	"""
	Shorthand for getting a memory value
	"""	
	def mem(self, addr):
	
		return self.s().memory.load(addr, endness = Endness.LE)
		
	"""
	Shorthand for getting a register
	"""	
	def reg(self):
	
		return self.s().regs
				
	"""
	Adds a new condition at the specified program counter
	"""
	def addCond(self, pc, cond):
			
		# Give this condition an index
		cond.i = self.count
		self.count+=1
			
		# Add condition to dict
		if pc in self.conds.keys():
			self.conds[pc].append(cond)
		else:
			self.conds[pc] = [cond]
	
	"""
	Steps simulation manager and checks conditions
	"""
	def execute(self, instructions=1):
		
		for i in range(instructions):
			# Save current pc as previous
			pc = self.s().regs.pc
			
			self.smgr.step(num_inst=1)
			
			# Todo- we can probably use state.history instead!
			self.prevPc = pc
			self.checkConditions(self.getPc())
	
	"""
	Checks all conditions at the given address
	"""
	def checkConditions(self, address):
	
		allPassed = True
		
		instrString = str(ArchSH4.LAST_LIFTED_INSTR.__class__).split('_')[-1][:-2]
			
		print("---------- PC = %s ---------- (%s)%s" % (str(hex(address)).replace('L',''),instrString,"*" if instrString not in self.instrs else ""))	
		
		# For debugging purposes, save instructions we've lifted
		self.instrs.add(instrString)
			
		if address in self.conds.keys():
		
			for cond in self.conds[address]:
			
				# Don't execute any condition twice
				if cond.i < self.execCount:
					continue
			
				self.execCount += 1
			
				# Register
				if cond.checkValue in self.mapping.keys():
					toCheck = self.mapping[cond.checkValue]()
				# Previous PC
				elif cond.checkValue == 'prevPc':
					toCheck = self.prevPc
				# Lambda
				elif callable(cond.checkValue):
					toCheck = cond.checkValue(self)
				# Memory
				else:
					toCheck = self.smgr.one_active.state.memory.load(cond.checkValue, endness = Endness.LE)
				
				# Support for lambdas
				if callable(cond.desiredValue):
					desiredValue = cond.desiredValue(self)
				else:
					desiredValue = cond.desiredValue
					
				# TODO refactor operators, maybe
				if cond.operation == '==':
					passed = (self.s().solver.eval(toCheck == desiredValue))
				elif cond.operation == '!=':
					passed = (self.s().solver.eval(toCheck != desiredValue))
				elif cond.operation == '& 1':
					passed = ((self.s().solver.eval(toCheck & 1)) == desiredValue)
				else:
					raise NotImplementedError("Bad operator.")
					
				if True or not passed:
					print("%s condition %s" % ("Passed" if passed else "***FAILED",cond.toString(toCheck)))
				
				if not passed:
					allPassed = False
					
		return allPassed
	
# We need to register the CC and lifter with angr	
angr.calling_conventions.register_default_cc('sh4', SimCCSH4LinuxSyscall)
pyvex.lifting.register(LifterSH4, 'sh4')