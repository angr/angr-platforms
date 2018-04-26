import abc
from arch_sh4 import ArchSH4
from pyvex.lifting.util import *
from pyvex.const import get_type_size
import bitstring
from bitstring import Bits
import logging
l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_32
HALFBYTE_TYPE = Type.int_4
BYTE_TYPE = Type.int_8
WORD_TYPE = Type.int_16
LWORD_TYPE = Type.int_32
INDEX_TYPE = Type.int_16
STATUS_REG_IND = 3
CARRY_BIT_IND = 0


##
## NOTE: The bitstream legend for this arch is:
# m: source
# n: destination
# b: byte/word flag
# i: immediate data
# d: displacement
# a: addressing mode
# s: operand size or sign/unsign
# g: > or >=
# c: constant post/pre increment

# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
	return Bits(bin=s).int

class SH4Instruction(Instruction):

	commit_func = None
	
	# Locations of SR reg bits
	bitPos = {'T' : 0, 'S' : 1, 'Q' : 8, 'M' : 9}

	# AO - Added args
	def __init__(self, bitstrm, arch, addr):
		super(SH4Instruction, self).__init__(bitstrm, arch, addr)
		#print(self)
		#print(self.bin_format)

	# Some common stuff we use around
	
	def get_pc(self):
		return self.get('pc', REGISTER_TYPE)

	# Adam - Not actually using any of this
	
	"""
	
	# Default flag handling
	def carry(self, *args):
		return None
	
	def get_sr(self):
		return self.get(STATUS_REG_IND, REGISTER_TYPE)


	def put_sr(self, val):
		return self.put(val, STATUS_REG_IND)

	def get_carry(self):
		return self.get_sr()[CARRY_BIT_IND]

	def commit_result(self, res):
		if self.commit_func != None:
			self.commit_func(res)

	def compute_flags(self, *args):
		'''
		Compute the flags touched by each instruction
		and store them in the status register
		'''
		c = self.carry(*args)
		if not c:
			return

		sreg = self.get_sr()
		# TODO: please check this out to make sure I compute it correctly
		sreg = sreg & ~(1 << offset) | (flag.cast_to(REGISTER_TYPE) << offset).cast_to(sreg.ty)
		self.put_sr(sreg)

	def resolve_reg(self, src_bit, dst_bit):
		src_bits = src_bit
		dst_bits = dst_bit
		src_num = int(src_bits, 2)
		dst_num = int(dst_bits, 2)
		src_name = ArchSH4.register_index[src_num]
		dst_name = ArchSH4.register_index[dst_num]
		return src_name, dst_name
	"""
		
	@abc.abstractmethod
	def fetch_operands(self):
		pass
		
	##############################################		
	# Adam's Code		
	# Based on instrs in: http://www.shared-ptr.com/sh_insns.html
	##############################################	
	
	"""
	Like Instruction's .put, except it checks the condition
	to decide what to put in the destination register
	
	TODO - maybe this should go in Instruction?
	"""
	def put_conditional(self, cond, valiftrue, valiffalse, reg):
	
		val = self.irsb_c.ite(cond.rdt , valiftrue.rdt, valiffalse.rdt)
		offset = self.lookup_register(self.irsb_c.irsb.arch, 'sr')
		self.irsb_c.put(val, offset)
	
	"""
	Wrapper for compute_result, since we need support for delayed branching
	"""
	def compute_result(self, *args):
		
		# For testing purposes only
		ArchSH4.LAST_LIFTED_INSTR = self
		
		ArchSH4.DELAYED_SET = False
		
		retVal = self.compute_result2(*args)
			
		# Handle a delayed jump, if one has been set
		if ArchSH4.DELAYED_DEST_PC is not None and not ArchSH4.DELAYED_SET:
					
			if isinstance(ArchSH4.DELAYED_DEST_PC, list):
			
				# Do something fancy
				if ArchSH4.DELAYED_DEST_PC[0] == "displace":
				
					pc = self.constant(ArchSH4.DELAYED_DEST_PC[1], LWORD_TYPE)
					
				else:
				
					raise NotImplementedError("Unimplemented delay instruction")
							
			else:
				# Copy some register value
				pc = self.get_reg_val(ArchSH4.DELAYED_DEST_PC)
		
			self.put(pc, 'pc')
			
			if ArchSH4.DELAYED_TYPE is not None:
			
				if ArchSH4.DELAYED_TYPE is False:
					self.jump(None, pc)
				else:
					self.jump(None, pc, jumpkind=ArchSH4.DELAYED_TYPE)
			
			# Reset state
			ArchSH4.DELAYED_DEST_PC = None
			ArchSH4.DELAYED_TYPE = None
			ArchSH4.DELAYED_SET = False		
			
		return retVal
			
	"""
	Compute system flags and return new candidate sr value (b/c of conditions)
	"""
	def set_flags(self, sr, **kwargs):
						
		for bitKey in kwargs:
		
			pos = self.bitPos[bitKey]
			val = kwargs[bitKey]
			
			if val:
				# Set bit
				sr = sr | (1 << pos)
			else:
				# Clear bit
				sr = sr & ~(1 << pos)
				
		return sr
				
	"""
	Get system flags
	"""
	def get_flag(self, flag, sr):
	
		pos = self.bitPos[flag]
		
		return (sr >> self.bitPos[flag]) & 1
		
	"""
	Increment the PC by 2, which is what most instructions do
	"""
	def inc_pc(self):
	
		# Only increment the PC if we are not about to jump!
		if ArchSH4.DELAYED_DEST_PC is None:
	
			pc_vv = self.get_pc()
			pc_vv += 2
			self.put(pc_vv, 'pc')
			#self.put(self.constant(self.addr + 2), 'pc')
		
	"""
	get referenced register name
	Gets the name of the register referenced by the specified letter
	in the instruction's bin_format
	"""
	def get_rreg(self, letter):
		return self.resolve_one_reg(int(self.data[letter], 2))
			
	"""
	get referenced register value
	Gets the VexValue of the register referenced by the specified letter
	in the instruction's bin_format
	"""
	def get_rreg_val(self, letter, ty = Type.int_32, extend = False, zerox = False):
		val = self.get(self.get_rreg(letter), ty)
		
		if extend:
			val = val.widen_signed(extend)
			
		if zerox:
			val = val.cast_to(zerox, signed=False)
			
		return val
		
	"""
	get referenced immediate value
	Gets the VexValue of the immediate value referenced by the specified letter in the instruction's bin_format
	"""
	def get_rimm_val(self, letter, ty = Type.int_32, extend = False, zerox = False):
		val = self.constant(int(self.data[letter], 2), ty)
		
		if extend:
			ty = extend
			val = val.widen_signed(extend)
			
		if zerox:
			ty = zerox
			val = val.cast_to(zerox, signed=False)
			
		return val
		
	"""
	get register value
	Gets the VexValue of the register with the specified name
	"""
	def get_reg_val(self, regname, ty = Type.int_32, extend = False, zerox = False):
		val = self.get(regname, ty)
		
		if extend:
			val = val.widen_signed(extend)
			
		if zerox:
			val = val.cast_to(zerox, signed=False)
			
		return val
			
	"""
	Converts the integer code of a register to its name
	"""
	def resolve_one_reg(self, int_code):
		return ArchSH4.register_index[int_code]
		
"""
Handle swap.b and swap.w
"""
class Instruction_SWAP(SH4Instruction):

	bin_format = '0110nnnnmmmm100t'
	name='swap'
	
	def fetch_operands(self):
				
		# Fetch the register values
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		print(self.disassemble())
		
		return rm, rn, rn_name
		
	def disassemble(self):
		
		if self.data['t'] == 0:
			self.name += '.b'
		else:
			self.name += '.w'
			
		return "%s %s,%s" % (self.name, self.get_rreg('m'), self.get_rreg('n'))

	def compute_result2(self, rm, rn, rn_name):
	
		# swap.b
		if self.data['t'] == 0:
			"""
			Swaps the upper and lower parts of the contents of general register Rm and stores the result in Rn. The 8 bits from bit 15 to bit 8 of Rm are swapped with the 8 bits from bit 7 to bit 0. The upper 16 bits of Rm are transferred directly to the upper 16 bits of Rn.
			"""
	
			temp0 = rm & 0xFFFF0000
			temp1 = (rm & 0x0000FFFF) << 8
			
			res = (rn | temp1 | temp0) + ( (rm & 0x0000FF00) >> 8 )
		
		# swap.w
		else:
			"""
			Swaps the upper and lower parts of the contents of general register Rm and stores the result in Rn. The 16 bits from bit 31 to bit 16 of Rm are swapped with the 16 bits from bit 15 to bit 0. 
			"""
		
			temp = (rm >> 16) & 0x0000FFFF
			res = (rm << 16) | temp
		
		self.put(res, rn_name)
	
		self.inc_pc()
	
		return res
		
class Instruction_XTRCT(SH4Instruction):

	bin_format = '0110nnnnmmmm1101'
	name='xtrct'
	
	def fetch_operands(self):
							
		# Fetch the registers
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		return rm, rn, rn_name
		
	def disassemble(self):
			
		return "%s %s,%s" % (self.name, self.get_rreg('m'), self.get_rreg('n'))

	def compute_result2(self, rm, rn, rn_name):
		"""
		Extracts the middle 32 bits from the 64-bit contents of linked general registers Rm and Rn, and stores the result in Rn. 
		"""
	
		res = ((rm << 16) & 0xFFFF0000) | ((rn >> 16) & 0x0000FFFF) 
		
		self.put(res, rn_name)
	
		self.inc_pc()
	
		return res	
		
class Instruction_EXTS(SH4Instruction):

	bin_format = '0110nnnnmmmm11dd'
	name='ext?.?'
	
	def fetch_operands(self):
	
		if self.data['d'] == '10':
			self.name = 'exts.b'
			rm = self.get_rreg_val('m',ty=BYTE_TYPE,extend=LWORD_TYPE)
		elif self.data['d'] == '11':
			self.name = 'exts.w'
			rm = self.get_rreg_val('m',ty=WORD_TYPE,extend=LWORD_TYPE)
		elif self.data['d'] == '00':
			self.name = 'extu.b'
			rm = self.get_rreg_val('m',ty=BYTE_TYPE,zerox=LWORD_TYPE)
		elif self.data['d'] == '01':
			self.name = 'extu.w'
			rm = self.get_rreg_val('m',ty=WORD_TYPE,zerox=LWORD_TYPE)
									
		rm_name = self.get_rreg('m')
		rn_name = self.get_rreg('n')

		return rm, rm_name, rn_name
		
	def disassemble(self):
	
		rm, rm_name, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn_name):
		"""
		Sign-extends the contents of general register Rm and stores the result in Rn. The value of Rm bit 7 is transferred to Rn bits 8 to 31. 
		
		Sign-extends the contents of general register Rm and stores the result in Rn. The value of Rm bit 15 is transferred to Rn bits 16 to 31. 
		
		Zero-extends the contents of general register Rm and stores the result in Rn. 0 is transferred to Rn bits 8 to 31. 
		
		Zero-extends the contents of general register Rm and stores the result in Rn. 0 is transferred to Rn bits 16 to 31. 
		"""
		
		# Note: are the ops in fetch_operands preferable to manual &'s?
		
		self.put(rm, rn_name)
					
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVBL(SH4Instruction):

	bin_format = '0110nnnnmmmm0000'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')

		return rm, rn_name
		
	def disassemble(self):
	
		rm, rn_name = self.fetch_operands()
			
		return "%s @%s,%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn_name):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		val = self.load(rm, Type.int_8)

		self.put(val.widen_signed(Type.int_32), rn_name)
	
		self.inc_pc()
	
		return val	
		
class Instruction_MOVWL(SH4Instruction):

	bin_format = '0110nnnnmmmm0001'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')

		return rm, rn_name
		
	def disassemble(self):
	
		rm, rn_name = self.fetch_operands()
			
		return "%s @%s,%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn_name):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		val = self.load(rm, Type.int_16)
		
		self.put(val.widen_signed(Type.int_32), rn_name)
	
		self.inc_pc()
	
		return val	
		
class Instruction_MOVLL(SH4Instruction):

	bin_format = '0110nnnnmmmm0010'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')

		return rm, rn_name
		
	def disassemble(self):
	
		rm, rn_name = self.fetch_operands()
			
		return "%s @%s,%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn_name):
		"""
		Transfers the source operand to the destination.
		"""
		
		val = self.load(rm, Type.int_32)
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val	

class Instruction_MOVLI(SH4Instruction):

	bin_format = '1101nnnndddddddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', BYTE_TYPE, zerox=LWORD_TYPE)
		rn_name = self.get_rreg('n')

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result2(self, pc, d, rn_name):
		"""
		Stores immediate data, sign-extended to longword, in general register Rn. The data is stored from memory address (PC + 4 + displacement * 4). The 8-bit displacement is multiplied by four after zero-extension, and so the relative distance from the operand is in the range up to PC + 4 + 1020 bytes. The PC value is the address of this instruction. A value with the lower 2 bits adjusted to 00 is used in address calculation. 
		"""
		
		toRead = ( (pc & 0xFFFFFFFC) + 4 + (d << 2) );
		
		val = self.load(toRead, Type.int_32)
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val	

class Instruction_MOV(SH4Instruction):

	bin_format = '0110nnnnmmmm0011'
	name='mov'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		rn_name = self.get_rreg('n')

		return rm, rm_name, rn_name
		
	def disassemble(self):
	
		rm, rm_name, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		self.put(rm, rn_name)
					
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVI(SH4Instruction):

	bin_format = '1110nnnniiiiiiii'
	name='mov'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i',ty=Type.int_8,extend=Type.int_32)
		rn_name = self.get_rreg('n')

		return i, rn_name
		
	def disassemble(self):
	
		i, rn_name = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, rn_name)

	def compute_result2(self, i, rn_name):
		"""
		Stores immediate data, sign-extended to longword, in general register Rn. 
		"""
		
		self.put(i, rn_name)
					
		self.inc_pc()
	
		return i	
		
class Instruction_MOVLS4(SH4Instruction):

	bin_format = '0001nnnnmmmmdddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		d = self.get_rimm_val('d', ty= HALFBYTE_TYPE,zerox=LWORD_TYPE)
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')

		return d, rm, rn
		
	def disassemble(self):
	
		d, rm, rn = self.fetch_operands()
			
		return "%s %s,@(%s,%s)" % (self.name, rm, d, rn)

	def compute_result2(self, d, rm, rn):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is multiplied by four after zero-extension, enabling a range up to +60 bytes to be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead. 
		"""
		
		#d = (0x000000FF & d); # done above!
		writeAddr = ( rn + (d << 2) );
		
		self.store(rm, writeAddr)
			
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVLL4(SH4Instruction):

	bin_format = '0101nnnnmmmmdddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		d = self.get_rimm_val('d', HALFBYTE_TYPE,zerox=LWORD_TYPE)
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')

		return d, rm, rn_name
		
	def disassemble(self):
	
		d, rm, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s), %s" % (self.name, rm, d, rn_name)

	def compute_result2(self, d, rm, rn_name):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is multiplied by four after zero-extension, enabling a range up to +60 bytes to be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead. 
		"""
		
		#d = (0x000000F & d);
		toRead = ( rm + (d << 2) );
		
		val = self.load(toRead, Type.int_32)
				
		self.put(val, rn_name)
					
		self.inc_pc()
	
		return val	

class Instruction_MOVW(SH4Instruction):

	bin_format = '1001nnnndddddddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', ty=Type.int_8, extend=LWORD_TYPE)
		rn_name = self.get_rreg('n')

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result2(self, pc, d, rn_name):
		"""
		Stores immediate data, sign-extended to longword, in general register Rn. The data is stored from memory address (PC + 4 + displacement * 2). The 8-bit displacement is multiplied by two after zero-extension, and so the relative distance from the table is in the range up to PC + 4 + 510 bytes. The PC value is the address of this instruction. 
		"""
		
		#d = (0x000000FF & d);
		toRead = ( pc + 4 + (d << 1) );
		
		val = self.load(toRead, Type.int_16)
		
		if (val & 0x8000) == 0:
			val = val & 0x0000FFFF
		else:
			val = val | 0xFFFF0000
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val		

class Instruction_MOVWL4(SH4Instruction):

	bin_format = '10000101mmmmdddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		d = self.get_rimm_val('d', HALFBYTE_TYPE, zerox=LWORD_TYPE)
		rm = self.get_rreg_val('m')

		return d, rm
		
	def disassemble(self):
	
		d, rm = self.fetch_operands()
			
		return "%s @(%s,%s),R0" % (self.name, d, rm)

	def compute_result2(self, d, rm):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is multiplied by two after zero-extension, enabling a range up to +30 bytes to be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead. The loaded data is sign-extended to 32 bit before being stored in the destination register.  
		"""
		
		toRead = ( rm + (d << 1) );
				
		# This should be 16 bit, but that should be handled below
		val = self.load(toRead, Type.int_16)
		
		self.put(val, 'r0')
			
		self.inc_pc()
	
		return val	
		
class Instruction_MOVBL4(SH4Instruction):

	bin_format = '10000100mmmmdddd'
	name='mov.b'
	
	def fetch_operands(self):
									
		d = self.get_rimm_val('d', HALFBYTE_TYPE, zerox=LWORD_TYPE)
		rm = self.get_rreg_val('m')

		return d, rm
		
	def disassemble(self):
	
		d, rm = self.fetch_operands()
			
		return "%s @(%s,%s),R0" % (self.name, d, rm)

	def compute_result2(self, d, rm):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is only zero-extended, so a range up to +15 bytes can be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
						
		val = self.load(rm + d , Type.int_8)
			
		self.put(val, 'r0')
			
		self.inc_pc()
	
		return val	
		
class Instruction_MOVBS(SH4Instruction):

	bin_format = '0010nnnnmmmm0000'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', ty=BYTE_TYPE)
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,@%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		self.store(rm, rn)
			
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVWS(SH4Instruction):

	bin_format = '0010nnnnmmmm0001'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', WORD_TYPE)
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,@%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		self.store(rm, rn)
			
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVLS(SH4Instruction):

	bin_format = '0010nnnnmmmm0010'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,@%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		self.store(rm, rn)
			
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVLM(SH4Instruction):

	bin_format = '0010nnnnmmmm0110'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		
		return rm, rn, rn_name
		
	def disassemble(self):
	
		rm, rn, rn_name = self.fetch_operands()
			
		return "%s %s,@-%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn, rn_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		rn = rn - 4
		self.put(rn, rn_name)
		
		self.store(rm, rn)
					
		self.inc_pc()
	
		return rm	

class Instruction_MOVWM(SH4Instruction):

	bin_format = '0010nnnnmmmm0101'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', WORD_TYPE)
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,@-%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		rn -= 2
		self.put(rn, rn_name)
		
		self.store(rm, rn)
					
		self.inc_pc()
	
		return rm		

class Instruction_MOVBM(SH4Instruction):

	bin_format = '0010nnnnmmmm0100'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', BYTE_TYPE)
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,@-%s" % (self.name, rm, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		rn -= 1
		self.put(rn, rn_name)
		
		self.store(rm, rn)		
					
		self.inc_pc()
	
		return rm	

class Instruction_MOVBL0(SH4Instruction):

	bin_format = '0000nnnnmmmm1100'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s @(r0,%s),%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		val = self.load(rm + r0, BYTE_TYPE).widen_signed(LWORD_TYPE)
			
		self.put(val, rn_name)
							
		self.inc_pc()
	
		return val	

class Instruction_MOVWL0(SH4Instruction):

	bin_format = '0000nnnnmmmm1101'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s @(r0,%s),%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		rn = self.load(rm + r0, WORD_TYPE).widen_signed(LWORD_TYPE)
		
		self.put(rn, rn_name)
							
		self.inc_pc()
	
		return rn	

class Instruction_MOVLL0(SH4Instruction):

	bin_format = '0000nnnnmmmm1110'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s @(r0,%s),%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination.
		"""
		
		rn = self.load(rm + r0, LWORD_TYPE)
				
		self.put(rn, rn_name)
							
		self.inc_pc()
	
		return rm	

class Instruction_MOVBS0(SH4Instruction):

	bin_format = '0000nnnnmmmm0100'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', BYTE_TYPE)
		rn = self.get_rreg_val('n')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s %s,@(r0,%s)" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination.
		"""
		
		self.store(rm, rn + r0)
							
		self.inc_pc()
	
		return rm

class Instruction_MOVWS0(SH4Instruction):

	bin_format = '0000nnnnmmmm0101'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m', WORD_TYPE)
		rn = self.get_rreg_val('n')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s %s,@(r0,%s)" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination.
		"""
		
		self.store(rm, rn + r0)
							
		self.inc_pc()
	
		return rm	

class Instruction_MOVLS0(SH4Instruction):

	bin_format = '0000nnnnmmmm0110'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		r0 = self.get_reg_val('r0')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name, r0
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name, r0 = self.fetch_operands()
			
		return "%s %s,@(r0,%s)" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name, r0):
		"""
		Transfers the source operand to the destination.
		"""
		
		self.store(rm, rn + r0)
							
		self.inc_pc()
	
		return rm	
		
class Instruction_MOVBP(SH4Instruction):

	bin_format = '0110nnnnmmmm0100'
	name='mov.b'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s @%s+,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register.

		"""
		
		# Todo - doing this the pyvex way, check correctness
		rn = self.load(rm, BYTE_TYPE).widen_signed(LWORD_TYPE)
				
		self.put(rn, rn_name)
		
		if (rn_name != rm_name):
			self.put(rm+1,rm_name)
							
		self.inc_pc()
	
		return rn			
		
class Instruction_MOVWP(SH4Instruction):

	bin_format = '0110nnnnmmmm0101'
	name='mov.w'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s @%s+,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. The loaded data is sign-extended to 32 bit before being stored in the destination register.
		"""
		
		# Todo - doing this the pyvex way, check correctness
		rn = self.load(rm, WORD_TYPE).widen_signed(LWORD_TYPE)
				
		self.put(rn, rn_name)
		
		if (rn_name != rm_name):
			self.put(rm+2,rm_name)
							
		self.inc_pc()
	
		return rn			
		
class Instruction_MOVLP(SH4Instruction):

	bin_format = '0110nnnnmmmm0110'
	name='mov.l'
	
	def fetch_operands(self):
									
		rm = self.get_rreg_val('m')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s @%s+,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Transfers the source operand to the destination. 
		"""
		
		# Todo - doing this the pyvex way, check correctness
		rn = self.load(rm, LWORD_TYPE)
				
		self.put(rn, rn_name)
		
		if (rn_name != rm_name):
			self.put(rm+4,rm_name)
							
		self.inc_pc()
	
		return rn	
		
class Instruction_MOVBS4(SH4Instruction):

	bin_format = '10000000nnnndddd'
	name='mov.b'
	
	def fetch_operands(self):
									
		r0 = self.get_reg_val('r0')
		d = self.get_rimm_val('d', HALFBYTE_TYPE, zerox=Type.int_32)
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return r0, d, rn_name, rn
		
	def disassemble(self):
	
		r0, d, rn_name, rn = self.fetch_operands()
			
		return "%s r0,@(%s,%s)" % (self.name, d, rn_name)

	def compute_result2(self, r0, d, rn_name, rn):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is only zero-extended, so a range up to +15 bytes can be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead. 
		"""
		
		self.store(r0.cast_to(Type.int_8), rn + d)
			
		self.inc_pc()
	
		return r0	
		
class Instruction_MOVWS4(SH4Instruction):

	bin_format = '10000001nnnndddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		r0 = self.get_reg_val('r0')
		d = self.get_rimm_val('d', HALFBYTE_TYPE, zerox=Type.int_32)
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return r0, d, rn_name, rn
		
	def disassemble(self):
	
		r0, d, rn_name, rn = self.fetch_operands()
			
		return "%s r0,@(%s,%s)" % (self.name, d, rn_name)

	def compute_result2(self, r0, d, rn_name, rn):
		"""
		Transfers the source operand to the destination. The 4-bit displacement is multiplied by two after zero-extension, enabling a range up to +30 bytes to be specified. If a memory operand cannot be reached, the @(R0,Rn) mode can be used instead.  
		"""
		
		self.store(r0.cast_to(Type.int_16), rn + (d << 1))
			
		self.inc_pc()
	
		return r0	
		
class Instruction_MOVBLG(SH4Instruction):

	bin_format = '11000100dddddddd'
	name='mov.b'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_8, zerox=Type.int_32)
		
		return gbr, d
		
	def disassemble(self):
	
		gbr, d = self.fetch_operands()
			
		return "%s @(%s,GBR),r0" % (self.name, d)

	def compute_result2(self, gbr, d):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is only zero-extended, so a range up to +255 bytes can be specified. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		# Check if correct! (load type should handle overflow)
		
		val = self.load(gbr + d, BYTE_TYPE).widen_signed(LWORD_TYPE)
		self.put(val, 'r0')
					
		self.inc_pc()
	
		return val	

class Instruction_MOVWLG(SH4Instruction):

	bin_format = '11000101dddddddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_8, zerox=Type.int_32)
		
		return gbr, d
		
	def disassemble(self):
	
		gbr, d = self.fetch_operands()
			
		return "%s @(%s,GBR),r0" % (self.name, d)

	def compute_result2(self, gbr, d):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is multiplied by two after zero-extension, enabling a range up to +510 bytes to be specified. The loaded data is sign-extended to 32 bit before being stored in the destination register. 
		"""
		
		d = d << 1
		
		# Check if correct! (load type should handle overflow)
		
		val = self.load(gbr + d, WORD_TYPE).widen_signed(LWORD_TYPE)
		self.put(val, 'r0')
					
		self.inc_pc()
	
		return val	

class Instruction_MOVLLG(SH4Instruction):

	bin_format = '11000110dddddddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_8, zerox=Type.int_32)
		
		return gbr, d
		
	def disassemble(self):
	
		gbr, d = self.fetch_operands()
			
		return "%s @(%s,GBR),r0" % (self.name, d)

	def compute_result2(self, gbr, d):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is multiplied by four after zero-extension, enabling a range up to +1020 bytes to be specified. 
		"""
		
		d = d << 2
				
		val = self.load(gbr + d, LWORD_TYPE)
		self.put(val, 'r0')
					
		self.inc_pc()
	
		return val		

class Instruction_MOVBSG(SH4Instruction):

	bin_format = '11000000dddddddd'
	name='mov.b'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_16, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return gbr, d, r0
		
	def disassemble(self):
	
		gbr, d,r0 = self.fetch_operands()
			
		return "%s r0,@(%s,GBR)" % (self.name, d)

	def compute_result2(self, gbr, d, r0):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is only zero-extended, so a range up to +255 bytes can be specified. 
		"""
		
		# Check if correct!
		
		self.store(r0.cast_to(BYTE_TYPE), gbr + d)
					
		self.inc_pc()
	
		return r0.cast_to(BYTE_TYPE)

class Instruction_MOVWSG(SH4Instruction):

	bin_format = '11000001dddddddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_16, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return gbr, d, r0
		
	def disassemble(self):
	
		gbr, d,r0 = self.fetch_operands()
			
		return "%s r0,@(%s,GBR)" % (self.name, d)

	def compute_result2(self, gbr, d, r0):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is multiplied by two after zero-extension, enabling a range up to +510 bytes to be specified. 
		"""
		
		d = d << 1
		
		# Check if correct!
		
		self.store(r0.cast_to(WORD_TYPE), gbr + d)
					
		self.inc_pc()
	
		return r0.cast_to(WORD_TYPE)	

class Instruction_MOVLSG(SH4Instruction):

	bin_format = '11000010dddddddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		gbr = self.get_reg_val('gbr')
		d = self.get_rimm_val('d', Type.int_8, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return gbr, d, r0
		
	def disassemble(self):
	
		gbr, d,r0 = self.fetch_operands()
			
		return "%s r0,@(%s,GBR)" % (self.name, d)

	def compute_result2(self, gbr, d, r0):
		"""
		Transfers the source operand to the destination. The 8-bit displacement is multiplied by four after zero-extension, enabling a range up to +1020 bytes to be specified. 
		"""
		
		d = d << 2
		
		# Check if correct!
		
		self.store(r0.cast_to(LWORD_TYPE), gbr + d)
					
		self.inc_pc()
	
		return r0			
		
# TODO Floating-Point Control Instructions

class Instruction_LDSFPUL(SH4Instruction):

	bin_format = '0100mmmm01011010'
	name='lds'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s %s,FPUL" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Loads the source operand into FPU system register FPUL. 
		"""
				
		self.put(rm, 'fpul')
					
		self.inc_pc()
	
		return rm

class Instruction_LDS_MACL(SH4Instruction):

	bin_format = '0100mmmm00011010'
	name='lds'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s %s,MACL" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register MACL. 
		"""
				
		self.put(rm, 'macl')
					
		self.inc_pc()
	
		return rm
		
class Instruction_LDS_PR(SH4Instruction):

	bin_format = '0100mmmm00101010'
	name='lds'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s %s,PR" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register PR. 
		"""
				
		self.put(rm, 'pr')
					
		self.inc_pc()
	
		return rm
		
class Instruction_LDSL_PR(SH4Instruction):

	bin_format = '0100mmmm00100110'
	name='lds.l'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s @%s+,PR" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register PR. 
		"""
		
		val = self.load(rm, LWORD_TYPE)
				
		self.put(val, 'pr')
		self.put(rm+4, rm_name)
					
		self.inc_pc()
	
		return val
		
class Instruction_LDSL_MACL(SH4Instruction):

	bin_format = '0100mmmm00010110'
	name='lds.l'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s @%s+,MACL" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register MACL. 
		"""
		
		val = self.load(rm, LWORD_TYPE)
				
		self.put(val, 'macl')
		self.put(rm+4, rm_name)
					
		self.inc_pc()
	
		return val

class Instruction_LDS(SH4Instruction):

	bin_format = '0100mmmm00001010'
	name='lds'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s %s,MACH" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register MACH. 
		"""
				
		self.put(rm, 'mach')
					
		self.inc_pc()
	
		return rm
		
class Instruction_LDSL(SH4Instruction):

	bin_format = '0100mmmm00000110'
	name='lds.l'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s @%s+,MACH" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Stores the source operand into the system register MACH. 
		"""
		
		val = self.load(rm, LWORD_TYPE)
				
		self.put(val, 'mach')
		self.put(rm+4, rm_name)
					
		self.inc_pc()
	
		return val

class Instruction_ROTL(SH4Instruction):

	bin_format = '0100nnnn00000100'
	name='rotl'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Rotates the contents of general register Rn one bit to the left, and stores the result in Rn. The bit rotated out of the operand is transferred to the T bit. 
		"""
		
		if ((rn & 0x80000000) == 0):
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)

		rn = rn << 1

		if (t == 1):
			rn = rn | 0x00000001
		else:
			rn = rn & 0xFFFFFFFE
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_ROTR(SH4Instruction):

	bin_format = '0100nnnn00000101'
	name='rotr'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		sr = self.get_reg_val('sr')
		
		return rn, rn_name, sr
				
	def disassemble(self):
	
		rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn, rn_name, sr):
		"""
		Rotates the contents of general register Rn one bit to the right, and stores the result in Rn. The bit rotated out of the operand is transferred to the T bit. 
		"""
		
		srT1 = self.set_flags(sr, T=1)
		srT0 = self.set_flags(sr, T=0)
		
		self.put_conditional((rn & 0x00000001) == 0, srT0, srT1, 'sr')
		
		self.put(rn >> 1, rn_name)
		
		self.inc_pc()

		
		"""if ((rn & 0x00000001) == 0):
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)

		rn = rn >> 1

		if (t == 1):
			rn = rn | 0x80000000
		else:
			rn = rn & 0x7FFFFFFF"""
		
					
# TODO fixme!
class Instruction_ROTCL(SH4Instruction):

	bin_format = '0100nnnn00100100'
	name='rotcl'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Rotates the contents of general register Rn one bit to the left through the T bit, and stores the result in Rn. The bit rotated out of the operand is transferred to the T bit. 
		"""
		
		if ((rn & 0x80000000) == 0):
			temp = 0
		else:
			temp = 1

		rn = rn << 1

		if (t == 1):
			rn = rn | 0x00000001
		else:
			rn = rn & 0xFFFFFFFE

		if temp == 1:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
# TODO fixme!
class Instruction_ROTCR(SH4Instruction):

	bin_format = '0100nnnn00100101'
	name='rotcr'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Rotates the contents of general register Rn one bit to the right through the T bit, and stores the result in Rn. The bit rotated out of the operand is transferred to the T bit. 
		"""
		
		if ((rn & 0x00000001) == 0):
			temp = 0
		else:
			temp = 1

		R[n] >>= 1;

		if (t == 1):
			rn = rn | 0x80000000
		else:
			rn = rn & 0x7FFFFFFF

		if temp == 1:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn

# TODO fixme and all other instructions that touch flags!
class Instruction_SHAD(SH4Instruction):

	bin_format = '0100nnnnmmmm1100'
	name='shad'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rn_name, rn, rm_name, rm
		
	def disassemble(self):
	
		rn_name, rn, rm_name, rm = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rn_name, rn, rm_name, rm):
		"""
		Arithmetically shifts the contents of general register Rn. General register Rm specifies the shift direction and the number of bits to be shifted.

		Rn register contents are shifted to the left if the Rm register value is positive, and to the right if negative. In a shift to the right, the MSB is added at the upper end.

		The number of bits to be shifted is specified by the lower 5 bits (bits 4 to 0) of the Rm register. If the value is negative (MSB = 1), the Rm register is represented as a two's complement. The left shift range is 0 to 31, and the right shift range, 1 to 32. 
		"""
		
		sgn = rm & 0x80000000

		if (sgn == 0):
			rn = rn << (rm & 0x1F)
		elif ((rm & 0x1F) == 0):
		
			if ((rn & 0x80000000) == 0):
				rn = 0
			else:
				rn = 0xFFFFFFFF
		else:
			rn = rn >> ((~rm & 0x1F) + 1);
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLD(SH4Instruction):

	bin_format = '0100nnnnmmmm1101'
	name='shld'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rn_name, rn, rm_name, rm
		
	def disassemble(self):
	
		rn_name, rn, rm_name, rm = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rn_name, rn, rm_name, rm):
		"""
		Logically shifts the contents of general register Rn. General register Rm specifies the shift direction and the number of bits to be shifted.

		Rn register contents are shifted to the left if the Rm register value is positive, and to the right if negative. In a shift to the right, 0s are added at the upper end.

		The number of bits to be shifted is specified by the lower 5 bits (bits 4 to 0) of the Rm register. If the value is negative (MSB = 1), the Rm register is represented as a two's complement. The left shift range is 0 to 31, and the right shift range, 1 to 32. 
		"""
		
		sgn = rm & 0x80000000

		if (sgn == 0):
			rn = rn << (rm & 0x1F)
		elif ((rm & 0x1F) == 0):
			rn = 0
		else:
			rn = rn.cast_to(LWORD_TYPE, signed=False) >> ((~rm & 0x1F) + 1);
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn

class Instruction_SHAR(SH4Instruction):

	bin_format = '0100nnnn00100001'
	name='shar'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Arithmetically shifts the contents of general register Rn one bit to the right and stores the result in Rn. The bit shifted out of the operand is transferred to the T bit. 
		"""
		
		if ((rn & 0x00000001) == 0):
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)

		if ((rn & 0x80000000) == 0):
			temp = 0
		else:
			temp = 1

		rn = rn >> 1

		if temp == 1:
			rn = rn | 0x80000000
		else:
			rn = rn & 0x7FFFFFFF
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHAL(SH4Instruction):

	bin_format = '0100nnnn00100000'
	name='shal'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Arithmetically shifts the contents of general register Rn one bit to the left and stores the result in Rn. The bit shifted out of the operand is transferred to the T bit. 
		"""
		
		if ((rn & 0x80000000) == 0):
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)

		rn = rn << 1
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn

class Instruction_SHLR(SH4Instruction):

	bin_format = '0100nnnn00000001'
	name='shll'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn one bit to the right and stores the result in Rn. The bit shifted out of the operand is transferred to the T bit. 
		"""
		
		if (rn & 0x00000001) == 0:
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)
			
		rn = rn >> 1
		rn = rn & 0x7FFFFFFF
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLR2(SH4Instruction):

	bin_format = '0100nnnn00001001'
	name='shlr2'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 2 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded.  
		"""
		
		rn = rn >> 2
		rn = rn & 0x3FFFFFFF
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLR8(SH4Instruction):

	bin_format = '0100nnnn00011001'
	name='shlr8'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 8 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded.  
		"""
		
		rn = rn >> 2
		rn = rn & 0x00FFFFFF
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLR16(SH4Instruction):

	bin_format = '0100nnnn00101001'
	name='shlr16'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 16 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded.  
		"""
		
		rn = rn >> 16
		rn = rn & 0x0000FFFF
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn

class Instruction_SHLL(SH4Instruction):

	bin_format = '0100nnnn00000000'
	name='shll'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		t = self.get_flag('T')

		return t, rn_name, rn
		
	def disassemble(self):
	
		t, rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, t, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn one bit to the left and stores the result in Rn. The bit shifted out of the operand is transferred to the T bit. 
		"""
		
		if (rn & 0x80000000) == 0:
			self.set_flags(T=0)
		else:
			self.set_flags(T=1)
			
		rn = rn << 1
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLL2(SH4Instruction):

	bin_format = '0100nnnn00001000'
	name='shll2'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 2 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded.  
		"""
		
		rn = rn << 2
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLL8(SH4Instruction):

	bin_format = '0100nnnn00011000'
	name='shll8'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 8 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded. 
		"""
		
		rn = rn << 8
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn
		
class Instruction_SHLL16(SH4Instruction):

	bin_format = '0100nnnn00101000'
	name='shll16'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')

		return rn_name, rn
		
	def disassemble(self):
	
		rn_name, rn = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn_name, rn):
		"""
		Logically shifts the contents of general register Rn 16 bits to the left and stores the result in Rn. The bits shifted out of the operand are discarded. 
		"""
		
		rn = rn << 16
		
		self.put(rn, rn_name)
					
		self.inc_pc()
	
		return rn

class Instruction_MOVT(SH4Instruction):

	bin_format = '0000nnnn00101001'
	name='movt'
	
	def fetch_operands(self):
									
		rn_name = self.get_rreg('n')
		
		# TODO - this operation must return either 0 or 1 as 32 bit
		T = self.get_flag('T')

		return T, rn_name
		
	def disassemble(self):
	
		T, rn_name = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, T, rn_name):
		"""
		Stores the T bit in general register Rn. The value of Rn is 1 when T = 1 and 0 when T = 0. 
		"""
		
		self.put(T, rn_name)
					
		self.inc_pc()
			
# TODO 0100nnnn00011011 (tas.b)		
		
class Instruction_TST(SH4Instruction):

	bin_format = '0010nnnnmmmm1000'
	name='tst'
	
	def fetch_operands(self):
									
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rn, sr
		
	def disassemble(self):
	
		rm, rn, sr = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm, rn, sr)

	def compute_result2(self, rm, rn, sr):
		"""
		ANDs the contents of general registers Rn and Rm, and sets the T bit if the result is zero. If the result is nonzero, the T bit is cleared. The contents of Rn are not changed. 
		"""
				
		"""
		val = self.irsb_c.ite( cond.rdt , (sr | 1).rdt, (sr & ~1).rdt )
		offset = self.lookup_register(self.irsb_c.irsb.arch, 'sr')
		self.irsb_c.put(val, offset)
		
		# using our new method...
		#self.put_conditional((rm & rn) == 0, (sr | 1), (sr & ~1), 'sr')		
		"""
		
		# This should also work, and is prettier (but less efficient)
		# TODO we could define a wrapper for these 3 calls
		
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional((rm & rn) == 0, srT, srF, 'sr')
		
		self.inc_pc()
					
class Instruction_TST_IMM(SH4Instruction):

	bin_format = '11001000iiiiiiii'
	name='tst'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return i, r0
		
	def disassemble(self):
	
		i, r0 = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, r0)

	def compute_result2(self, i, r0):
		"""
		ANDs the contents of general register R0 and the zero-extended immediate value and sets the T bit if the result is zero. If the result is nonzero, the T bit is cleared. The contents of Rn are not changed.

		Note
		Since the 8-bit immediate value is zero-extended, this instruction can only be used to test the lower 8 bits of R0.  
		"""
		
		# TODO - should we do this and skip the compute_flags method?
				
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional((r0 & i) == 0, srT, srF, 'sr')
		
		self.inc_pc()
		
class Instruction_TST_GBR(SH4Instruction):

	bin_format = '11001100iiiiiiii'
	name='tst'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8, extend=Type.int_32)
		r0 = self.get_reg_val('r0')
		gbr = self.get_reg_val('gbr')
		
		return i, r0, gbr
		
	def disassemble(self):
	
		i, r0, gbr = self.fetch_operands()
			
		return "%s #%s,@(%s,%s)" % (self.name, i, r0, gbr)

	def compute_result2(self, i, r0, gbr):
		"""
		ANDs the contents of the memory byte indicated by the indirect GBR address with the zero-extended immediate value and sets the T bit if the result is zero. If the result is nonzero, the T bit is cleared. The contents of the memory byte are not changed. 
		"""
		
		temp = self.load(r0 + gbr, BYTE_TYPE)
		
		temp = temp & i
				
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(temp == 0, srT, srF, 'sr')
									
		self.inc_pc()
		
class Instruction_XOR(SH4Instruction):

	bin_format = '0010nnnnmmmm1010'
	name='xor'
	
	def fetch_operands(self):
									
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		XORs the contents of general registers Rn and Rm and stores the result in Rn. 
		"""
				
		self.put(rm ^ rn, rn_name)
							
		self.inc_pc()
	
		
class Instruction_XOR_IMM(SH4Instruction):

	bin_format = '11001010iiiiiiii'
	name='xor'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return i, r0
		
	def disassemble(self):
	
		i, r0 = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, r0)

	def compute_result2(self, i, r0):
		"""
		XORs the contents of general register R0 and the zero-extended immediate value and stores the result in R0.

		Note
		Since the 8-bit immediate value is zero-extended, the upper 24 bits of R0 are not modified. 
		"""
				
		self.put(r0 ^ i, 'r0')
							
		self.inc_pc()
			
class Instruction_XOR_GBR(SH4Instruction):

	bin_format = '11001110iiiiiiii'
	name='xor.b'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8)
		r0 = self.get_reg_val('r0')
		gbr = self.get_reg_val('gbr')
		
		return i, r0, gbr
		
	def disassemble(self):
	
		i, r0, gbr = self.fetch_operands()
			
		return "%s #%s,@(%s,%s)" % (self.name, i, r0, gbr)

	def compute_result2(self, i, r0, gbr):
		"""
		XORs the contents of the memory byte indicated by the indirect GBR address with the immediate value and writes the result back to the memory byte. 
		"""
		
		temp = self.load(r0 + gbr, BYTE_TYPE)
		
		temp = temp & i
		
		self.store(temp, r0 + gbr)
							
		self.inc_pc()
			
class Instruction_NOT(SH4Instruction):

	bin_format = '0110nnnnmmmm0111'
	name='not'
	
	def fetch_operands(self):
									
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		Finds the one's complement of the contents of general register Rm and stores the result in Rn. That is, it inverts the Rm bits and stores the result in Rn.
		"""
				
		self.put(~rm, rn_name)
							
		self.inc_pc()
			
class Instruction_AND(SH4Instruction):

	bin_format = '0010nnnnmmmm1001'
	name='and'
	
	def fetch_operands(self):
									
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		ANDs the contents of general registers Rn and Rm and stores the result in Rn. 
		"""
				
		self.put(rm & rn, rn_name)
							
		self.inc_pc()
			
class Instruction_AND_IMM(SH4Instruction):

	bin_format = '11001001iiiiiiii'
	name='and'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8)
		r0 = self.get_reg_val('r0')
		
		return i, r0
		
	def disassemble(self):
	
		i, r0 = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, r0)

	def compute_result2(self, i, r0):
		"""
		ANDs the contents of general register R0 and the zero-extended immediate value and stores the result in R0.

		Note
		Since the 8-bit immediate value is zero-extended, the upper 24 bits of R0 are not modified. 
		"""
				
		self.put(r0 & i, 'r0')
							
		self.inc_pc()
			
class Instruction_AND_GBR(SH4Instruction):

	bin_format = '11001101iiiiiiii'
	name='and.b'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8)
		r0 = self.get_reg_val('r0')
		gbr = self.get_reg_val('gbr')
		
		return i, r0, gbr
		
	def disassemble(self):
	
		i, r0, gbr = self.fetch_operands()
			
		return "%s #%s,@(%s,%s)" % (self.name, i, r0, gbr)

	def compute_result2(self, i, r0, gbr):
		"""
		ANDs the contents of the memory byte indicated by the indirect GBR address with the immediate value and writes the result back to the memory byte. 
		"""
		
		temp = self.load(r0 + gbr, BYTE_TYPE)
		
		temp = temp & i
		
		self.store(temp, r0 + gbr)
							
		self.inc_pc()
			
class Instruction_OR(SH4Instruction):

	bin_format = '0010nnnnmmmm1011'
	name='or'
	
	def fetch_operands(self):
									
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')
		rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		
		return rm, rn, rn_name, rm_name
		
	def disassemble(self):
	
		rm, rn, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rn, rn_name, rm_name):
		"""
		ORs the contents of general registers Rn and Rm and stores the result in Rn. 
		"""
				
		self.put(rm | rn, rn_name)
							
		self.inc_pc()
			
class Instruction_OR_IMM(SH4Instruction):

	bin_format = '11001011iiiiiiii'
	name='or'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8, zerox=Type.int_32)
		r0 = self.get_reg_val('r0')
		
		return i, r0
		
	def disassemble(self):
	
		i, r0 = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, r0)

	def compute_result2(self, i, r0):
		"""
		ORs the contents of general register R0 and the zero-extended immediate value and stores the result in R0.

		Note
		Since the 8-bit immediate value is zero-extended, the upper 24 bits of R0 are not modified. 
		"""
				
		self.put(r0 | i, 'r0')
							
		self.inc_pc()
			
class Instruction_OR_GBR(SH4Instruction):

	bin_format = '11001111iiiiiiii'
	name='or.b'
	
	def fetch_operands(self):
									
		i = self.get_rimm_val('i', ty=Type.int_8)
		r0 = self.get_reg_val('r0')
		gbr = self.get_reg_val('gbr')
		
		return i, r0, gbr
		
	def disassemble(self):
	
		i, r0, gbr = self.fetch_operands()
			
		return "%s #%s,@(%s,%s)" % (self.name, i, r0, gbr)

	def compute_result2(self, i, r0, gbr):
		"""
		ORs the contents of the memory byte indicated by the indirect GBR address with the immediate value and writes the result back to the memory byte. 
		"""
		
		temp = self.load(r0 + gbr, BYTE_TYPE)
		
		temp = temp | i
		
		self.store(temp, r0 + gbr)
							
		self.inc_pc()
	
class Instruction_MOVA(SH4Instruction):

	bin_format = '11000111dddddddd'
	name='mova'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', ty=Type.int_8,zerox=Type.int_32)
		rn_name = 'r0'

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result2(self, pc, d, rn_name):
		"""
		Stores the effective address of the source operand into general register R0. The 8-bit displacement is zero-extended and quadrupled. Consequently, the relative interval from the operand is PC + 1020 bytes. The PC is the address four bytes after this instruction, but the lowest two bits of the PC are fixed at 00.
		"""
		
		val = ( (pc & 0xFFFFFFFC) + 4 + (d << 2) );
				
		self.put(val, rn_name)
	
		self.inc_pc()
	
class Instruction_FLDS(SH4Instruction):

	bin_format = '1111mmmm00011101'
	name='flds'
	
	def fetch_operands(self):
									
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')

		return rm_name, rm
		
	def disassemble(self):
	
		rm_name, rm = self.fetch_operands()
			
		return "%s %s,FPUL" % (self.name, rm_name)

	def compute_result2(self, rm_name, rm):
		"""
		Transfers the contents of floating-point register FRm into system register FPUL. 
		"""
				
		self.put(rm, 'fpul')
	
		self.inc_pc()
			
class Instruction_FSTS(SH4Instruction):

	bin_format = '1111nnnn00001101'
	name='fsts'
	
	def fetch_operands(self):
									
		FPUL = self.get_reg_val('fpul')
		rn_name = self.get_rreg('n')

		return FPUL, rn_name
		
	def disassemble(self):
	
		FPUL, rn_name = self.fetch_operands()
			
		return "%s FPUL,%s" % (self.name, rn_name)

	def compute_result2(self, FPUL, rn_name):
		"""
		Transfers the contents of system register FPUL to floating-point register FRn. 
		"""
				
		self.put(FPUL, rn_name)
	
		self.inc_pc()
	
class Instruction_STSFPSCR(SH4Instruction):

	bin_format = '0000nnnn01101010'
	name='sts'
	
	def fetch_operands(self):
									
		fpscr = self.get_reg_val('fpscr')
		rn_name = self.get_rreg('n')

		return fpscr, rn_name
		
	def disassemble(self):
	
		fpscr, rn_name = self.fetch_operands()
			
		return "%s FPSCR,%s" % (self.name, rn_name)

	def compute_result2(self, fpscr, rn_name):
		"""
		Stores system register FPSCR in the destination. 
		"""
				
		self.put(fpscr, rn_name)
	
		self.inc_pc()
			
class Instruction_STSFPUL(SH4Instruction):

	bin_format = '0000nnnn01011010'
	name='sts'
	
	def fetch_operands(self):
									
		fpul = self.get_reg_val('fpul')
		rn_name = self.get_rreg('n')

		return fpul, rn_name
		
	def disassemble(self):
	
		fpul, rn_name = self.fetch_operands()
			
		return "%s FPUL,%s" % (self.name, rn_name)

	def compute_result2(self, fpul, rn_name):
		"""
		Stores system register FPUL in the destination. 
		"""
				
		self.put(fpul, rn_name)
	
		self.inc_pc()
			
class Instruction_STS_MACH(SH4Instruction):

	bin_format = '0000nnnn00001010'
	name='sts'
	
	def fetch_operands(self):
									
		mach = self.get_reg_val('mach')
		rn_name = self.get_rreg('n')

		return mach, rn_name
		
	def disassemble(self):
	
		mach, rn_name = self.fetch_operands()
			
		return "%s mach,%s" % (self.name, rn_name)

	def compute_result2(self, mach, rn_name):
		"""
		Stores system register MACH in the destination. 
		"""
				
		self.put(mach, rn_name)
	
		self.inc_pc()
			
class Instruction_STS_MACL(SH4Instruction):

	bin_format = '0000nnnn00011010'
	name='sts'
	
	def fetch_operands(self):
									
		macl = self.get_reg_val('macl')
		rn_name = self.get_rreg('n')

		return macl, rn_name
		
	def disassemble(self):
	
		macl, rn_name = self.fetch_operands()
			
		return "%s macl,%s" % (self.name, rn_name)

	def compute_result2(self, macl, rn_name):
		"""
		Stores system register MACL in the destination. 
		"""
				
		self.put(macl, rn_name)
	
		self.inc_pc()
			
class Instruction_STS_PR(SH4Instruction):

	bin_format = '0000nnnn00101010'
	name='sts'
	
	def fetch_operands(self):
									
		pr = self.get_reg_val('pr')
		rn_name = self.get_rreg('n')

		return pr, rn_name
		
	def disassemble(self):
	
		pr, rn_name = self.fetch_operands()
			
		return "%s pr,%s" % (self.name, rn_name)

	def compute_result2(self, pr, rn_name):
		"""
		Stores system register PR in the destination. 
		"""
				
		self.put(pr, rn_name)
	
		self.inc_pc()
			
class Instruction_STSL_MACH(SH4Instruction):

	bin_format = '0100nnnn00000010'
	name='sts.l'
	
	def fetch_operands(self):
									
		mach = self.get_reg_val('mach')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		return mach, rn, rn_name
		
	def disassemble(self):
	
		mach, rn, rn_name = self.fetch_operands()
			
		return "%s mach,@-%s" % (self.name, rn_name)

	def compute_result2(self, mach, rn_name):
		"""
		Stores system register MACH in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(mach, rn)
					
		self.inc_pc()
	
class Instruction_STSL_MACL(SH4Instruction):

	bin_format = '0100nnnn00000010'
	name='sts.l'
	
	def fetch_operands(self):
									
		macl = self.get_reg_val('macl')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		return macl, rn, rn_name
		
	def disassemble(self):
	
		macl, rn, rn_name = self.fetch_operands()
			
		return "%s MACL,@-%s" % (self.name, rn_name)

	def compute_result2(self, macl, rn_name):
		"""
		Stores system register MACL in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(macl, rn)
					
		self.inc_pc()
	
class Instruction_STSLPR(SH4Instruction):

	bin_format = '0100nnnn00100010'
	name='sts.l'
	
	def fetch_operands(self):
									
		pr = self.get_reg_val('pr')
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		return pr, rn, rn_name
		
	def disassemble(self):
	
		pr, rn, rn_name = self.fetch_operands()
			
		return "%s pr,@-%s" % (self.name, rn_name)

	def compute_result2(self, pr, rn, rn_name):
		"""
		Stores system register pr in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(pr, rn)
					
		self.inc_pc()
			
class Instruction_CLRMAC(SH4Instruction):

	bin_format = '0000000000101000'
	name='clrmac'
	
	def fetch_operands(self):								
		pass
		
	def disassemble(self):
		return self.name

	def compute_result2(self):
		"""
		Clears the MACH and MACL registers. 
		"""
				
		self.put(0, 'mach')
		self.put(0, 'macl')
							
		self.inc_pc()
		
class Instruction_CLRS(SH4Instruction):

	bin_format = '0000000001001000'
	name='clrs'
	
	def fetch_operands(self):	

		sr = self.get_reg_val('sr')
		return [sr]
		
	def disassemble(self):
	
		return self.name

	def compute_result2(self, sr):
		"""
		Clears the S bit
		"""
		
		sr = self.set_flags(sr, S=0)
		
		self.put(sr, 'sr')
							
		self.inc_pc()

class Instruction_CLRT(SH4Instruction):

	bin_format = '0000000000001000'
	name='clrt'
	
	def fetch_operands(self):	

		sr = self.get_reg_val('sr')
		return [sr]
		
	def disassemble(self):
	
		return self.name

	def compute_result2(self, sr):
		"""
		Clears the T bit
		"""
		
		sr = self.set_flags(sr, T=0)
		
		self.put(sr, 'sr')
							
		self.inc_pc()
		
class Instruction_NOP(SH4Instruction):

	bin_format = '0000000000001001'
	name='nop'
	
	def fetch_operands(self):	
		# Lol?
		return []
		
	def disassemble(self):
		return self.name

	def compute_result2(self):
		"""
		No operation
		"""
									
		self.inc_pc()
		
class Instruction_NEG(SH4Instruction):

	bin_format = '0110nnnnmmmm1011'
	name='neg'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Finds the two's complement of the contents of general register Rm and stores the result in Rn. That is, it subtracts Rm from 0 and stores the result in Rn. 
		"""
				
		self.put(0 - rm, rn_name)
	
		self.inc_pc()
	
# TODO fixme!	
class Instruction_NEG_C(SH4Instruction):

	bin_format = '0110nnnnmmmm1010'
	name='negc'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		T = self.get_flag('T')
		
		return T, rm, rm_name, rn, rn_name
		
	def disassemble(self):
	
		T, rm, rm_name, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, T, rm, rm_name, rn_name):
		"""
		Subtracts the contents of general register Rm and the T bit from 0 and stores the result in Rn. A borrow resulting from the operation is reflected in the T bit. This instruction can be used for sign inversion of a value exceeding 32 bits.

		Note
		This instruction can also be used to efficiently store the reversed T bit value in a general register, if the MOVRT instruction is not available.  
		"""
		
		temp = 0 - rm
		val = temp - T
		
		self.put(val, rn_name)
				
		if 0 < temp:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
			
		if temp < val:
			self.set_flags(T=1)
	
		self.inc_pc()
	
		return val	

class Instruction_SUB(SH4Instruction):

	bin_format = '0011nnnnmmmm1000'
	name='sub'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Subtracts the contents of general register Rm from the contents of general register Rn and stores the result in Rn. For immediate data subtraction, ADD #imm,Rn should be used. 
		"""
				
		self.put(rn - rm, rn_name)
	
		self.inc_pc()
			
class Instruction_DMULU(SH4Instruction):

	bin_format = '0011nnnnmmmm0101'
	name='dmulu.l'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Performs 32-bit multiplication of the contents of general register Rn by the contents of Rm, and stores the 64-bit result in the MACH and MACL registers. The multiplication is performed as an unsigned arithmetic operation. 
		"""
		
		RnL = rn & 0x0000FFFF
		RnH = (rn >> 16) & 0x0000FFFF

		RmL = rm & 0x0000FFFF
		RmH = (rm >> 16) & 0x0000FFFF

		temp0 = RmL * RnL
		temp1 = RmH * RnL
		temp2 = RmL * RnH
		temp3 = RmH * RnH

		Res2 = 0
		Res1 = temp1 + temp2
		if (Res1 < temp1):
			Res2 += 0x00010000

		temp1 = (Res1 << 16) & 0xFFFF0000
		Res0 = temp0 + temp1
		if (Res0 < temp0):
			Res2+=1

		Res2 = Res2 + ((Res1 >> 16) & 0x0000FFFF) + temp3
		
		self.put(Res2, 'mach')
		self.put(Res0, 'macl')
	
		self.inc_pc()
	
		return Res2,Res0	
		
class Instruction_DMULS(SH4Instruction):

	bin_format = '0011nnnnmmmm1101'
	name='dmuls.l'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Performs 32-bit multiplication of the contents of general register Rn by the contents of Rm, and stores the 64-bit result in the MACH and MACL registers. The multiplication is performed as a signed arithmetic operation. 
		"""

		tempn = rn
		tempm = rm

		if (tempn < 0):
			tempn = 0 - tempn

		if (tempm < 0):
			tempm = 0 - tempm

		if ((rn ^ rn) < 0):
			fnLmL = -1
		else:
			fnLmL = 0

		temp1 = tempn
		temp2 = tempm

		RnL = temp1 & 0x0000FFFF
		RnH = (temp1 >> 16) & 0x0000FFFF

		RmL = temp2 & 0x0000FFFF
		RmH = (temp2 >> 16) & 0x0000FFFF

		temp0 = RmL * RnL
		temp1 = RmH * RnL
		temp2 = RmL * RnH
		temp3 = RmH * RnH

		Res2 = 0
		Res1 = temp1 + temp2
		if (Res1 < temp1):
			Res2 += 0x00010000

		temp1 = (Res1 << 16) & 0xFFFF0000
		Res0 = temp0 + temp1
		if (Res0 < temp0):
			Res2+=1

		Res2 = Res2 + ((Res1 >> 16) & 0x0000FFFF) + temp3

		if (fnLmL < 0):
		
			Res2 = ~Res2;
			if (Res0 == 0):
				Res2+=1
			else:
				Res0 = (~Res0) + 1
		
		self.put(Res2, 'mach')
		self.put(Res0, 'macl')
	
		self.inc_pc()
	
		return Res2,Res0	
		
class Instruction_MUL(SH4Instruction):

	bin_format = '0000nnnnmmmm0111'
	name='mul'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Performs 32-bit multiplication of the contents of general registers Rn and Rm, and stores the lower 32 bits of the result in the MACL register. The contents of MACH are not changed. 
		"""
				
		self.put(rn * rm, 'macl')
	
		self.inc_pc()
	
		return val	
		
class Instruction_MUL_W(SH4Instruction):

	bin_format = '0010nnnnmmmm111d'
	name='mul?.w'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')	
			
		if self.data['d'] == '1':
			self.name = 'muls.w'
			rm = rm.cast_to(WORD_TYPE, signed=True)
			rn = rn.cast_to(WORD_TYPE, signed=True)
		elif seld.data['d'] == '0':
			self.name = 'mulu.w'
			rm = rm.cast_to(WORD_TYPE, signed=False)
			rn = rn.cast_to(WORD_TYPE, signed=False)

		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Performs 16-bit multiplication of the contents of general registers Rn and Rm, and stores the 32-bit result in the MACL register. The multiplication is performed as a signed arithmetic operation. The contents of MACH are not changed. 
		
		Performs 16-bit multiplication of the contents of general registers Rn and Rm, and stores the 32-bit result in the MACL register. The multiplication is performed as an unsigned arithmetic operation. The contents of MACH are not changed. 
		"""
				
		self.put(rn * rm, 'macl')
	
		self.inc_pc()
			
# TODO - this is probably not fully correct
class Instruction_MAC_L(SH4Instruction):

	bin_format = '0000nnnnmmmm1111'
	name='mac.l'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')	
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		S = self.get_flag('S')
		MACH = self.get_reg_val('mach')
		MACL = self.get_reg_val('macl')
		
		return rn, rm, rn_name, rm_name, S, MACH, MACL
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name, _, _, _ = self.fetch_operands()
			
		return "%s @%s+,@%s+" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name, S, MACH, MACL):
		"""
		Performs signed multiplication of the 32-bit operands whose addresses are the contents of general registers Rm and Rn, adds the 64-bit result to the MAC register contents, and stores the result in the MAC register. Operands Rm and Rn are each incremented by 4 each time they are read.

		When the S bit is cleared to 0, the 64-bit result is stored in the coupled MACH and MACL registers.

		When bit S is set to 1, addition to the MAC register is a saturation operation of 48 bits starting from the LSB. For the saturation operation, only the lower 48 bits of the MACL register are enabled and the result is limited to a range of 0xFFFF800000000000 (minimum) and 0x00007FFFFFFFFFFF (maximum).

		Note
		On SH4, when MAC*/MUL* is followed by an STS.L MAC*,@-Rn instruction, the latency of MAC*/MUL* is 5 cycles. In the case of consecutive executions of MAC.W/MAC.L, the latency is decreased to 2 cycles. 
		"""
		
		tempn = self.load(rn, LWORD_TYPE)
		tempm = self.load(rm, LWORD_TYPE)

		self.put(rn + 4, rn_name)
		self.put(rm + 4, rm_name)

		if (tempn ^ tempm) < 0:
			fnLmL = -1
		else:
			fnLmL = 0

		if (tempn < 0):
			tempn = 0 - tempn
		if (tempm < 0):
			tempm = 0 - tempm

		temp1 = tempn
		temp2 = tempm

		RnL = temp1 & 0x0000FFFF
		RnH = (temp1 >> 16) & 0x0000FFFF
		RmL = temp2 & 0x0000FFFF
		RmH = (temp2 >> 16) & 0x0000FFFF
		temp0 = RmL * RnL
		temp1 = RmH * RnL
		temp2 = RmL * RnH
		temp3 = RmH * RnH

		Res2 = 0

		Res1 = temp1 + temp2
		if (Res1 < temp1):
			Res2 += 0x00010000

		temp1 = (Res1 << 16) & 0xFFFF0000

		Res0 = temp0 + temp1;
		if (Res0 < temp0):
			Res2+=1

		Res2 = Res2 + ((Res1 >> 16) & 0x0000FFFF) + temp3;

		if(fnLmL < 0):
		
			Res2 = ~Res2;
			if (Res0 == 0):
				Res2+=1
			else:
				Res0 = (~Res0) + 1
		

		if S == 1:
		
			Res0 = MACL + Res0;
			if (MACL > Res0):
				Res2+=1

			Res2 += MACH & 0x0000FFFF;

			if ((Res2 < 0) and (Res2 < 0xFFFF8000)):
				Res2 = 0xFFFF8000
				Res0 = 0x00000000

			if ((Res2 > 0) and (Res2 > 0x00007FFF)):
			
				Res2 = 0x00007FFF
				Res0 = 0xFFFFFFFF

			MACH = (Res2 & 0x0000FFFF) | (MACH & 0xFFFF0000)
			MACL = Res0
						
			self.put(MACH, 'mach')
			self.put(MACL, 'macl')

		else:
		
			Res0 = MACL + Res0
			if (MACL > Res0):
				Res2 +=1

			Res2 += MACH;
			MACH = Res2
			MACL = Res0
			
			self.put(MACH, 'mach')
			self.put(MACL, 'macl')
		
		self.inc_pc()
	
		return MACH, MACL	
	
# TODO - this is probably not fully correct
class Instruction_MAC_W(SH4Instruction):

	bin_format = '0100nnnnmmmm1111'
	name='mac.w'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')	
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		S = self.get_flag('S')
		MACH = self.get_reg_val('mach')
		MACL = self.get_reg_val('macl')
		
		return rn, rm, rn_name, rm_name, S, MACH, MACL
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name, _, _, _ = self.fetch_operands()
			
		return "%s @%s+,@%s+" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name, S, MACH, MACL):
		"""
		Performs signed multiplication of the 16-bit operands whose addresses are the contents of general registers Rm and Rn, adds the 32-bit result to the MAC register contents, and stores the result in the MAC register. Operands Rm and Rn are each incremented by 2 each time they are read.

		If the S bit is 0, a 16 * 16 + 64 -> 64-bit multiply-and-accumulate operation is performed, and the 64-bit result is stored in the linked MACH and MACL registers.

		If the S bit is 1, a 16 * 16 + 32 -> 32-bit multiply-and-accumulate operation is performed, and the addition to the MAC register contents is a saturation operation. In a saturation operation, only the MACL register is valid, and the result range is limited to 0x80000000 (minimum value) to 0x7FFFFFFF (maximum value). If overflow occurs, the LSB of the MACH register is set to 1. 0x80000000 (minimum value) is stored in the MACL register if the result overflows in the negative direction, and 0x7FFFFFFF (maximum value) is stored if the result overflows in the positive direction

		Note
		When the S bit is 0, the SH2 and SH-DSP CPU perform a 16 * 16 + 64 -> 64 bit multiply and accumulate operation and the SH1 CPU performs a 16 * 16 + 42 -> 42 bit multiply and accumulate operation.

		On SH4, when MAC*/MUL* is followed by an STS.L MAC*,@-Rn instruction, the latency of MAC*/MUL* is 5 cycles. In the case of consecutive executions of MAC.W/MAC.L, the latency is decreased to 2 cycles. 
		"""
		
		tempn = self.load(rn, WORD_TYPE)
		tempm = self.load(rm, WORD_TYPE)

		self.put(rn + 2, rn_name)
		self.put(rm + 2, rm_name)
		
		templ = MACL;
		tempm = tempn * tempm;

		if MACL >= 0:
			dest = 0
		else:
			dest = 1

		if tempm >= 0:
			src = 0
			tempn = 0
		else:
			src = 1
			tempn = 0xFFFFFFFF
		
		src += dest;
		MACL += tempm;

		if MACL >= 0:
			ans = 0
		else:
			ans = 1

		ans += dest;

		if (S == 1):
		
			if (ans == 1):
			
				if (src == 0):
					MACL = 0x7FFFFFFF
				if (src == 2):
					MACL = 0x80000000
		
		else:
			MACH += tempn;
			if (templ > MACL):
				MACH += 1	
		
		self.put(MACH, 'mach')
		self.put(MACL, 'macl')
		
		self.inc_pc()
		
		return MACH, MACL	
		
class Instruction_DIV0S(SH4Instruction):

	bin_format = '0010nnnnmmmm0111'
	name='div0s'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Performs initial settings for signed division. This instruction is followed by a DIV1 instruction that executes 1-digit division, for example, and repeated division steps are executed to find the quotient. See the description of the DIV1 instruction for details.

		Note
		This instruction can also be used to compare the signs of Rm and Rn. If the signs of Rm and Rn are equal, T will be set to 0. If the signs of Rm and Rn are not equal, T will be set to 1.  
		"""
		
		if ((rn & 0x80000000) == 0):
			q = 0
		else:
			q = 1

		if ((rm & 0x80000000) == 0):
			m = 0
		else:
			m = 1

		t = (not (m == q))
		
		self.set_flags(T=t,M=m,Q=q)
	
		self.inc_pc()
	
		return val	
		
# TODO do flags correctly
class Instruction_DIV0U(SH4Instruction):

	bin_format = '0000000000011001'
	name='div0u'
	
	def fetch_operands(self):
			
		return []
		
	def disassemble(self):
		
		return "%s" % (self.name)

	def compute_result2(self, garbage):
		"""
		Performs initial settings for unsigned division. This instruction is followed by a DIV1 instruction that executes 1-digit division, for example, and repeated division steps are executed to find the quotient. See the description of the DIV1 instruction for details.  
		"""
				
		self.set_flags(T=0,M=0,Q=0)
	
		self.inc_pc()
	
		return val	

# TODO check this!
class Instruction_DIV1(SH4Instruction):

	bin_format = '0011nnnnmmmm0100'
	name='div1'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')
		q = self.get_flag('Q')
		t = self.get_flag('T')
		m = self.get_flag('M')

		return rn, rm, rn_name, rm_name, q, t, m
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name, _, _, _ = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name, q, t, m):
		"""
		Performs 1-digit division (1-step division) of the 32-bit contents of general register Rn (dividend) by the contents of Rm (divisor). The quotient is obtained by repeated execution of this instruction alone or in combination with other instructions. The specified registers and the M, Q, and T bits must not be modified during these repeated executions.

		In 1-step division, the dividend is shifted 1 bit to the left, the divisor is subtracted from this, and the quotient bit is reflected in the Q bit according to whether the result is positive or negative.

		Detection of division by zero or overflow is not provided. Check for division by zero and overflow division before executing the division. A remainder operation is not provided. Find the remainder by finding the product of the divisor and the obtained quotient, and subtracting this value from the dividend:
		remainder = dividend - (divisor * quotient)

		Initial settings should first be made with the DIV0S or DIV0U instruction. DIV1 is executed once for each bit of the divisor. If a quotient of more than 17 bits is required, place an ROTCL instruction before the DIV1 instruction. See the examples for details of the division sequence. 
		"""
		
		old_q = q
		q = (0x80000000 & rn) != 0
		tmp2 = rm
		rn = rn << 1
		rn = rn | t
		
		if (old_q == 0):
		
			if (m == 0):
			
			  tmp0 = rn
			  rn -= tmp2
			  tmp1 = rn > tmp0;

			  if (q == 0):
				q = tmp1
			  elif (q == 1):
				q = tmp1 == 0

			elif (m == 1):
			
				tmp0 = rn
				rn += tmp2
				tmp1 = rn < tmp0

				if (q == 0):
					q = (tmp1 == 0)
				elif (q == 1):
					q = tmp1

		elif (old_q == 1):
		
			if (m == 0):
			
				tmp0 = rn
				rn += tmp2
				tmp1 = rn < tmp0

				if (q == 0):
					q = tmp1
				elif (q == 1):
					q = (tmp1 == 0)

			elif (m == 1):
			
				tmp0 = rn
				rn -= tmp2
				tmp1 = rn > tmp0

				if (q == 0):
					q = (tmp1 == 0)
				elif (q == 1):
					q = tmp1

		t = (q == m)
		
		self.put(rn, rn_name)
		self.set_flags(T=t,Q=q)
	
		self.inc_pc()
	
		return rn	
		
class Instruction_DT(SH4Instruction):

	bin_format = '0100nnnn00010000'
	name='dt'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rn_name = self.get_rreg('n')

		return rn, rn_name
		
	def disassemble(self):
	
		rn, rn_name = self.fetch_operands()
			
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn, rn_name):
		"""
		Decrements the contents of general register Rn by 1 and compares the result with zero. If the result is zero, the T bit is set to 1. If the result is nonzero, the T bit is cleared to 0. 
		"""
		
		val = rn - 1
		
		self.put(val, rn_name)
		
		if val == 0:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
	
		self.inc_pc()
	
		return val			
		
class Instruction_ADD(SH4Instruction):

	bin_format = '0011nnnnmmmm1100'
	name='add'
	
	def fetch_operands(self):
			
		rn = self.get_rreg_val('n')
		rm = self.get_rreg_val('m')
		rn_name = self.get_rreg('n')
		rm_name = self.get_rreg('m')

		return rn, rm, rn_name, rm_name
		
	def disassemble(self):
	
		rn, rm, rn_name, rm_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rm_name)

	def compute_result2(self, rn, rm, rn_name, rm_name):
		"""
		Adds together the contents of general registers Rn and Rm and stores the result in Rn. 
		"""
		
		val = rn + rm
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val	

class Instruction_ADDI(SH4Instruction):

	bin_format = '0111nnnniiiiiiii'
	name='add'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		i = self.get_rimm_val('i', ty=Type.int_8,extend=Type.int_32)
		
		return i, rn, rn_name
		
	def disassemble(self):
	
		i,rn, rn_name = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, rn_name)

	def compute_result2(self, i, rn, rn_name):
		"""
		Adds together the contents of general register Rn and the immediate value and stores the result in Rn. The 8-bit immediate value is sign-extended to 32 bits, which allows it to be used for immediate subtraction or decrement operations. 
		"""
		
		val = i + rn
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val	
		
class Instruction_SUB_C(SH4Instruction):

	bin_format = '0011nnnnmmmm1010'
	name='subc'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		T = self.get_flag('T')
		
		return T, rm, rm_name, rn, rn_name
		
	def disassemble(self):
	
		T, rm, rm_name, rn, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, T, rm, rm_name, rn, rn_name):
		"""
		Subtracts the contents of general register Rm and the T bit from the contents of general register Rn, and stores the result in Rn. A borrow resulting from the operation is reflected in the T bit. This instruction is used for subtractions exceeding 32 bits.

		Note
		This instruction can also be used to store the T bit to all the bits of a general register. 
		"""
		
		tmp1 = rn - rm
		tmp0 = rn
		
		val = tmp1 - T
		
		self.put(val, rn_name)
		
		if tmp0 < tmp1:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
			
		if tmp1 < val:
			self.set_flags(T=1)
	
		self.inc_pc()
	
		return val	
		
class Instruction_SUB_V(SH4Instruction):

	bin_format = '0011nnnnmmmm1011'
	name='subv'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		
		return rm, rm_name, rn, rn_name
		
	def disassemble(self):
	
		rm, rm_name, rn, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name):
		"""
		Subtracts the contents of general register Rm from the contents of general register Rn, and stores the result in Rn. If underflow occurs, the T bit is set. 
		"""
		
		if rn >= 0:
			dest = 0
		else:
			dest = 1

		if rm >= 0:
			src = 0
		else:
			src = 1
	
		src += dest
		
		val = rn - rm
		
		self.put(val, rn_name)
		
		if val >= 0:
			ans = 0
		else:
			ans = 1

		ans += dest

		if src == 1:
			if ans == 1:
				newT = 1
			else:
				newT = 0
		else:
			newT = 0
		
		self.set_flags(T=newT)
		
		self.inc_pc()
	
		return val		

class Instruction_ADD_C(SH4Instruction):

	bin_format = '0011nnnnmmmm1110'
	name='addc'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		T = self.get_flag('T')
		
		return T, rm, rm_name, rn, rn_name
		
	def disassemble(self):
	
		T, rm, rm_name, rn, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, T, rm, rm_name, rn, rn_name):
		"""
		Adds together the contents of general registers Rn and Rm and the T bit, and stores the result in Rn. A carry resulting from the operation is reflected in the T bit. This instruction can be used to implement additions exceeding 32 bits. 
		"""
		
		tmp1 = rn + rm
		tmp0 = rn
		
		val = tmp1 + T
		
		self.put(val, rn_name)
		
		if tmp0 > tmp1:
			self.set_flags(T=1)
		else:
			self.set_flags(T=0)
			
		if tmp1 > val:
			self.set_flags(T=1)
	
		self.inc_pc()
	
		return val	

class Instruction_ADD_V(SH4Instruction):

	bin_format = '0011nnnnmmmm1111'
	name='addv'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		
		return rm, rm_name, rn, rn_name
		
	def disassemble(self):
	
		rm, rm_name, rn, rn_name = self.fetch_operands()
			
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name):
		"""
		Adds together the contents of general registers Rn and Rm and stores the result in Rn. If overflow occurs, the T bit is set. 
		"""
		
		if rn >= 0:
			dest = 0
		else:
			dest = 1

		if rm >= 0:
			src = 0
		else:
			src = 1
	
		src += dest
		
		val = rn + rm
		
		self.put(val, rn_name)
		
		if val >= 0:
			ans = 0
		else:
			ans = 1

		ans += dest

		if src == 0 or src == 2:
			if ans == 1:
				newT = 1
			else:
				newT = 0
		else:
			newT = 0
		
		self.set_flags(T=newT)
		
		self.inc_pc()
	
		return val		

class Instruction_BRA(SH4Instruction):

	bin_format = '1010dddddddddddd'
	name='bra'
	
	def fetch_operands(self):
		
		d = int(self.data['d'], 2)
		
		return [d]
		
	def disassemble(self):
	
		d = self.fetch_operands()
			
		return "%s PC+4+%s" % (self.name, d[0] * 2)

	def compute_result2(self, d):
		"""
		This is an unconditional branch instruction. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BRA instruction address. As the 12-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -4096 to +4094 bytes from the BRA instruction. If the branch destination cannot be reached, this branch can be performed with a JMP instruction.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""

		if (d & 0x800) == 0:
			d = (0x00000FFF & d)
		else:
			d = (0xFFFFF000 | d)
		
		d = 4 + (d << 1)
		
		self.inc_pc()
		# When this gets executed, pc will be incremented by 2 already
		ArchSH4.DELAYED_DEST_PC = ["displace", d]
		ArchSH4.DELAYED_SET = True
			
class Instruction_BT(SH4Instruction):

	bin_format = '10001001dddddddd'
	name='bt'
	
	def fetch_operands(self):
		
		sr = self.get_reg_val('sr')
		d = int(self.data['d'], 2)
		
		return sr,d
		
	def disassemble(self):
	
		sr,d = self.fetch_operands()
			
		# TODO - make pretty
		return "%s %s" % (self.name, d)

	def compute_result2(self, sr, d):
		"""
		Description
		This is a conditional branch instruction that references the T bit. The branch is taken if T = 1, and not taken if T = 1. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BF instruction address. As the 8-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -256 to +254 bytes from the BF instruction.

		Note
		If the branch destination cannot be reached, the branch must be handled by using BF in combination with a BRA or JMP instruction, for example. 
		"""
		
		if ((d & 0x80) == 0):
			d = (0x000000FF & d)
		else:
			d = (0xFFFFFF00 | d)
		
		addr = self.constant(self.addr + 4 + (d << 1), LWORD_TYPE)
				
		# This has to happen if we don't branch
		self.inc_pc()
		
		self.jump((sr & 1) == 1, addr)
		self.jump((sr & 1) == 0, self.constant(self.addr + 2, LWORD_TYPE))

class Instruction_BF(SH4Instruction):

	bin_format = '10001011dddddddd'
	name='bf'
	
	def fetch_operands(self):
		
		sr = self.get_reg_val('sr')
		d = int(self.data['d'], 2)
		
		return sr,d
		
	def disassemble(self):
	
		sr,d = self.fetch_operands()
			
		# TODO - make pretty
		return "%s %s" % (self.name, d)

	def compute_result2(self, sr, d):
		"""
		Description
		This is a conditional branch instruction that references the T bit. The branch is taken if T = 0, and not taken if T = 1. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BF instruction address. As the 8-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -256 to +254 bytes from the BF instruction.

		Note
		If the branch destination cannot be reached, the branch must be handled by using BF in combination with a BRA or JMP instruction, for example. 
		"""
		
		if ((d & 0x80) == 0):
			d = (0x000000FF & d)
		else:
			d = (0xFFFFFF00 | d)
		
		addr = self.constant(self.addr + 4 + (d << 1), LWORD_TYPE)
				
		self.jump((sr & 1) == 0, addr)
		self.jump((sr & 1) == 1, self.constant(self.addr + 2, LWORD_TYPE))

		#if ((sr >> self.bitPos['T']) & 1) == 0:
				
class Instruction_JMP(SH4Instruction):

	bin_format = '0100mmmm00101011'
	name='jmp'
	
	def fetch_operands(self):
		
		#rm = self.get_rreg_val('m')
		rm_name = self.get_rreg('m')
		
		return [rm_name]
		
	def disassemble(self):
	
		rm_name = self.fetch_operands()
			
		return "%s @%s" % (self.name, rm_name)

	def compute_result2(self, rm_name):
		"""
		Unconditionally makes a delayed branch to the address specified by Rm.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""

		self.inc_pc()
		ArchSH4.DELAYED_DEST_PC = rm_name
		ArchSH4.DELAYED_TYPE = False
		ArchSH4.DELAYED_SET = True
					
class Instruction_JSR(SH4Instruction):

	bin_format = '0100mmmm00001011'
	name='jsr'
	
	def fetch_operands(self):
		
		rm_name = self.get_rreg('m')
		pc = self.get_reg_val('pc')
		
		return rm_name, pc
		
	def disassemble(self):
	
		rm_name, pc = self.fetch_operands()
			
		return "%s %s" % (self.name, rm_name)

	def compute_result2(self, rm_name, pc):
		"""
		Description
		Makes a delayed branch to the subroutine procedure at the specified address after execution of the following instruction. Return address (PC + 4) is saved in PR, and a branch is made to the address indicated by general register Rm. JSR is used in combination with RTS for subroutine procedure calls.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""
		
		self.put(pc + 4, 'pr')
		self.inc_pc()
		ArchSH4.DELAYED_DEST_PC = rm_name
		ArchSH4.DELAYED_TYPE = JumpKind.Call
		ArchSH4.DELAYED_SET = True
	
class Instruction_RTS(SH4Instruction):

	bin_format = '0000000000001011'
	name='rts'
	
	def fetch_operands(self):
			
		return []
		
	def disassemble(self):
				
		return self.name

	def compute_result2(self):
		"""
		Description
		Returns from a subroutine procedure by restoring the PC from PR. Processing continues from the address indicated by the restored PC value. This instruction can be used to return from a subroutine procedure called by a BSR or JSR instruction to the source of the call.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 		
		"""

		# inc_pc MUST() happen before we set ArchSH4.DELAYED_DEST_PC
		# always set DELAYED_SET to True if lifting a delayed branch instruction
		self.inc_pc()
		ArchSH4.DELAYED_TYPE = JumpKind.Ret
		ArchSH4.DELAYED_DEST_PC = 'pr'	
		ArchSH4.DELAYED_SET = True

class Instruction_CMPEQIM(SH4Instruction):

	bin_format = '10001000iiiiiiii'
	name='cmp/eq'
	
	def fetch_operands(self):
		
		r0 = self.get_reg_val('r0')
		i = self.get_rimm_val('i')
		sr = self.get_reg_val('sr')
		
		return r0, i, sr
		
	def disassemble(self):
	
		r0, i, sr = self.fetch_operands()
				
		return "%s #%s,r0" % (self.name)

	def compute_result2(self, r0, i, sr):
		"""
		Compares general register R0 and the sign-extended 8-bit immediate data and sets the T bit if the values are equal. If they are not equal the T bit is cleared. The contents of R0 are not changed.  		
		"""

		if ((i & 0x80) == 0):
			imm = (0x000000FF & i);
		else:
			imm = (0xFFFFFF00 | i);
			
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(r0 == imm, srT, srF, 'sr')

		self.inc_pc()					

class Instruction_CMPEQ(SH4Instruction):

	bin_format = '0011nnnnmmmm0000'
	name='cmp/eq'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if they are equal. The contents of Rn and Rm are not changed. 	
		"""
		
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rm == rn, srT, srF, 'sr')
	
		self.inc_pc()				
		
class Instruction_CMPHS(SH4Instruction):

	bin_format = '0011nnnnmmmm0010'
	name='cmp/hs'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if Rn is greater or equal Rm. The values for the comparison are interpreted as unsigned integer values. The contents of Rn and Rm are not changed. 		
		"""
		
		rm = rm.cast_to(LWORD_TYPE, signed=False)
		rn = rn.cast_to(LWORD_TYPE, signed=False)

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn >= rm, srT, srF, 'sr')
	
		self.inc_pc()			
		
class Instruction_CMPGE(SH4Instruction):

	bin_format = '0011nnnnmmmm0011'
	name='cmp/ge'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if Rn is greater or equal Rm. The values for the comparison are interpreted as signed integer values. The contents of Rn and Rm are not changed. 		
		"""

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn >= rm, srT, srF, 'sr')
	
		self.inc_pc()	
				
class Instruction_CMPSTR(SH4Instruction):

	bin_format = '0010nnnnmmmm1100'
	name='cmp/str'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if any of the 4 bytes in Rn are equal to the corresponding byte in Rm. The contents of Rn and Rm are not changed.

		Note
		This instruction can be used to speed up some string operations such as finding the string length of a zero terminated string or string matching.  		
		"""

		temp = rn ^ rm;
		HH = (temp & 0xFF000000) >> 24
		HL = (temp & 0x00FF0000) >> 16
		LH = (temp & 0x0000FF00) >> 8
		LL = temp & 0x000000FF
		HH = HH and HL and LH and LL

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(HH == 0, srT, srF, 'sr')
	
		self.inc_pc()			
			
class Instruction_CMPHI(SH4Instruction):

	bin_format = '0011nnnnmmmm0110'
	name='cmp/hi'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if Rn is greater Rm. The values for the comparison are interpreted as unsigned integer values. The contents of Rn and Rm are not changed. 			
		"""
				
		rm = rm.cast_to(LWORD_TYPE, signed=False)
		rn = rn.cast_to(LWORD_TYPE, signed=False)
		
		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn > rm, srT, srF, 'sr')
			
		self.inc_pc()					
		
class Instruction_CMPGT(SH4Instruction):

	bin_format = '0011nnnnmmmm0111'
	name='cmp/gt'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		rm_name = self.get_rreg('m')
		rm = self.get_rreg_val('m')
		sr = self.get_reg_val('sr')
		
		return rm, rm_name, rn, rn_name, sr
				
	def disassemble(self):
	
		rm, rm_name, rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s,%s" % (self.name, rm_name, rn_name)

	def compute_result2(self, rm, rm_name, rn, rn_name, sr):
		"""
		Compares general registers Rn and Rm, and sets the T bit if Rn is greater Rm. The values for the comparison are interpreted as signed integer values. The contents of Rn and Rm are not changed. 		
		"""

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn > rm, srT, srF, 'sr')
						
		self.inc_pc()				
								
class Instruction_CMPPL(SH4Instruction):

	bin_format = '0100nnnn00010101'
	name='cmp/pl'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		sr = self.get_reg_val('sr')
		
		return rn, rn_name, sr
				
	def disassemble(self):
	
		rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn, rn_name, sr):
		"""
		Compares general register Rn and sets the T bit if Rn is greater than 0. The value in Rn for the comparison is interpreted as signed integer. The contents of Rn are not changed. 	
		"""

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn > 0, srT, srF, 'sr')
		
class Instruction_CMPPZ(SH4Instruction):

	bin_format = '0100nnnn00010001'
	name='cmp/pz'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		sr = self.get_reg_val('sr')
		
		return rn, rn_name, sr
				
	def disassemble(self):
	
		rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn, rn_name, sr):
		"""
		Compares general register Rn and sets the T bit if Rn is greater than or equal to 0. The value in Rn for the comparison is interpreted as signed integer. The contents of Rn are not changed. 	
		"""

		srT = self.set_flags(sr, T=1)
		srF = self.set_flags(sr, T=0)
		
		self.put_conditional(rn >= 0, srT, srF, 'sr')
		
class Instruction_ROTL(SH4Instruction):

	bin_format = '0100nnnn00000100'
	name='rotl'
	
	def fetch_operands(self):
		
		rn_name = self.get_rreg('n')
		rn = self.get_rreg_val('n')
		sr = self.get_reg_val('sr')
		
		return rn, rn_name, sr
				
	def disassemble(self):
	
		rn, rn_name, sr = self.fetch_operands()
				
		return "%s %s" % (self.name, rn_name)

	def compute_result2(self, rn, rn_name, sr):
		"""
		Rotates the contents of general register Rn one bit to the left, and stores the result in Rn. The bit rotated out of the operand is transferred to the T bit. 	
		"""
				
		srT1 = self.set_flags(sr, T=1)
		srT0 = self.set_flags(sr, T=0)
		
		self.put_conditional((rn & 0x80000000) == 0, srT0, srT1, 'sr')
				
		# TODO we probably don't need all the bitwise stuff
		#self.put_conditional((rn & 0x80000000) == 0, (rn << 1) & 0xFFFFFFFE, (rn << 1) | 0x00000001, rn_name)

		self.put(rn << 1, rn_name)
		
		self.inc_pc()								
		
'''
# Caution: this will match anything, 
# so make sure all other instrs are implemented
# TODO - do we need to specify this?
class Instruction_WORD(SH4Instruction):

	bin_format = 'dddddddddddddddd'
	name='.word'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', LWORD_TYPE)

		return pc, d
		
	def disassemble(self):
	
		pc, d = self.fetch_operands()
			
		return ".word %s" % (self.name, d)

	def compute_result2(self, pc, d):
		"""
		Stores 1 word of data at the PC location
		"""
		
		self.store(pc, d.cast_to(WORD_TYPE))
	
		self.inc_pc()
	
		return d	
'''	
##############################################		
# End Adam's Code		
##############################################		
	
'''	
class Instruction_MOV_Rm_Rn(SH4Instruction):
	# I defined this based on my intuition
	# a: 01 -> @Rm, Rn # 00 -> Rm, @Rn
	# s: 00 -> mov.b, 01 -> mov.w, 10 -> mov.l, 11 -> mov
	bin_format = '0a10nnnnmmmm0css'
	name = 'mov'

	def compute_result2(self, src, dst):
		adr_mode = self.data['a']
		const = self.data['c']
		dst_num = int(self.data['n'], 2)
		src_num = int(self.data['m'], 2)
		# MOV.X Rm, @-Rn
		if adr_mode == '0' and const == '1':
			self.put(dst, dst_num)
		# MOV.X @Rm+, Rn
		elif adr_mode == '1' and const == '1':
			# Fetch the register
			reg_vv = self.get(src_num, REGISTER_TYPE)
			# Compute type
			ty = Type.int_8 if self.data['s'] == '00' \
							else  Type.int_16 if self.data['s'] == '01' \
							else Type.int_32
			# Post-increment
			if dst_num == src_num:
				reg_vv += get_type_size(ty)/8
			else:
				reg_vv = src
			self.put(reg_vv, src_num)
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		return src
	def disassemble(self):
		if self.data['s'] == '00':
			self.name = self.name + ".b"
		elif self.data['s'] == '01':
			self.name = self.name + ".w"
		elif self.data['s'] == '10':
			self.name = self.name + ".l"
		else:
			self.name = self.name
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		if self.data['a'] == '00':
			if self.data['c'] == '00':
				# mov.x Rm, @Rn
				src = src_name
				dst = '@' + dst_name
			else:
				# mov.x Rm, @-Rn
				src = src_name
				dst = '@-' + dst_name
		else:
			if self.data['c'] == '00':
				if self.data['s'] == '11':
					# mov Rm, Rn
					src = src_name
					dst = dst_name
				else:
					# mov.x @Rm, Rn
					src = '@' + src_name
					dst = dst_name
			else:
				# mov.x @Rm+, Rn
				src = '@' + src_name + '+'
				dst = dst_name
		return self.addr, self.name, [src, dst]

	def fetch_operands(self):
		ty = Type.int_8 if self.data['s'] == '00' \
						else  Type.int_16 if self.data['s'] == '01' \
						else Type.int_32
		src, dst, self.commit_func = self.fetch_reg(self.data['m'], self.data['n'], self.data['a'], self.data['c'], ty)
		return src, dst

	def fetch_reg(self, src_bits, dst_bits, adr_mode, const, ty):
		"""
		Resolve the operand for various mov instructions working with registers
		:param reg_src: The Source Operand Bits
		:param reg_dst: The Destination Operand Bits
		:param adr_mode: The Adderessing Mode associated with instruction
		:param const: The Constant post/pre Increment value
		:param ty: The Type (byte/word/longword)
		:return: The VexValue of the Operands, and the writeout function, if any
		"""
		src_num = int(src_bits, 2)
		dst_num = int(dst_bits, 2)
		if adr_mode == '1':
			# MOV.X @Rm, Rn
			if const == '0':
				# Fetch the register
				reg_vv = self.get(src_num, REGISTER_TYPE)
				# Load byte/word/lword from memory
				adr_val = self.load(reg_vv, ty)
				# Sign-extend the loaded data
				val_signed = adr_val.widen_signed(ty)
				src_vv = val_signed
				val = dst_num
				# In case extension didn't work! use this one as an alternative
				# val = adr_val & 0x000000ff if adr_val & 0x80 ==0 else \
				# adr_val | 0xffffff00
				writeout = lambda v: self.put(v, dst_num)
			# MOV.X @Rm+, Rn
			# TODO: complete commit_result
			# (src, dst, self.commit_result) -> (src_vv, val, writeout)
			# Idea: define a bit vector to distinguish two/one write-outs
			elif const == '1':
				# Fetch the register
				reg_vv = self.get(src_num, REGISTER_TYPE)
				# Load byte/word/lword from memory
				adr_val = self.load(reg_vv, ty)
				# Sign-extend the loaded data
				val_signed = adr_val.widen_signed(ty)
				src_vv = val_signed
				# Rm post-incremented by 1/2/4
				if src_num != dst_num:
					reg_vv += get_type_size(ty)/8
				# in case both refer to the same register
				else:
					reg_vv = val
				# Rm <- reg_vv, Rn <- val
				writeout = lambda v: self.put(v, dst_num)
		elif adr_mode == '0':
			# MOV.X Rm, @Rn
			if const == '0':
				# Fetch the register
				reg_vv = self.get(src_num, REGISTER_TYPE)
				adr_val = self.get(dst_num, REGISTER_TYPE)
				# Sign-extend the loaded data
				src_vv = reg_vv.widen_signed(REGISTER_TYPE)
				val = adr_val.widen_signed(REGISTER_TYPE)
				writeout = lambda v: self.store(v, val)
			# MOV.X Rm, @Rn-
			# TODO: complete commit_result
			# (src, dst, self.commit_result) -> (src_vv, val, writeout)
			# Idea: define a bit vector to distinguish two/one write-outs
			elif const == '1':
				# Fetch the register
				reg_vv = self.get(src_num, REGISTER_TYPE)
				adr_vv = self.get(dst_num, REGISTER_TYPE)
				# Sign-extend the loaded data
				src_vv = reg_vv.widen_signed(REGISTER_TYPE)
				val = adr_vv.widen_signed(REGISTER_TYPE)
				# Rn pre-decremented by 1/2/4
				val -= get_type_size(ty)/8
				# (Rn-size) <- Rm
				writeout = lambda v: self.store(v, val)
		return src_vv, val, writeout

		
		
class Instruction_XOR_Rm_Rn(SH4Instruction):
	bin_format = '0010nnnnmmmm1010'
	name = 'xor'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src, dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		return src ^ dst


class Instruction_XOR_imm(SH4Instruction):

	bin_format = '1100ss10iiiiiiii'
	name = 'xor'

	def fetch_operands(self):
		# Get #imm value
		src = int(self.data['i'], 2)
		# Fetch the register
		r0 = self.get('r0', REGISTER_TYPE)
		# (R0 + GBR) ^ (zero extend)imm -> (R0 + GBR)
		if self.data['s'] == '11':
			# Fetch the register
			gbr_vv = self.get('gbr', REGISTER_TYPE)
			adr = gbr_vv + r0
			# Load byte from memory
			adr_val = self.load(adr, BYTE_TYPE)
			dst = adr_val
		elif self.data['s'] == '10':
			dst = r0
		self.commit_result = lambda v: self.store(v, 'r0')
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '10' else self.name + '.b'
		return self.addr. self.name, ['#imm', 'R0']

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		ret = src ^ dst
		# Write_8 (GBR + R[0], temp) -> narrow_int just to make sure it's 8-bit
		return ret if self.data['s'] == '10' else ret.cast_to(BYTE_TYPE)


class Instruction_TST(SH4Instruction):
	# perform test-and-set operation on contents of Rm, Rn
	bin_format = '0010nnnnmmmm1000'
	name = 'tst'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		return src, dst

	def disassemle(self):
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src, dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		# ((R[n] & R[m]), T <- 0, T <- 1)
		return src & dst

	# decide on the value of T-bit in SR reg
	def carry(self, src, dst, ret):
		return True if ret == 0 else False


class Instruction_TST_imm(SH4Instruction):
	# I defined this based on my own intuition
	# s: 10 -> tst, 11 -> tst.b
	bin_format = '1100ss00iiiiiiii'
	name = 'tst'

	def fetch_operands(self):
		# Get #imm value
		imm_vv = int(self.data['i'], 2)
		src = imm_vv
		# Fetch the register
		r0_vv = self.get('r0', REGISTER_TYPE)
		if self.data['s'] == '10':
			dst = r0_vv
		elif self.data['s'] == '11':
			# Fetch the register
			gbr_vv = self.get('gbr', REGISTER_TYPE)
			adr = gbr_vv + r0_vv
			# Load byte from memory
			adr_val = self.load(adr, BYTE_TYPE)
			dst = adr_val
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '10' else self.name + '.b'
		return self.addr. self.name, ['#imm', 'R0' if self.data['s'] == '10' else '@(R0, GBR)']

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		# (R0 & (0x000000FF & (long)#imm)), T <- 0, T <- 1)
		ret = src & dst
		return ret

	# decide on the value of T-bit in SR reg
	def carry(self, src, dst, ret):
		return True if ret == 0 else False


class Instruction_OR(SH4Instruction):
	bin_format = '0010nnnnmmmm1011'
	name = 'or'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src , dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		ret = src | dst
		return ret


class Instruction_OR_imm(SH4Instruction):
	# I defined this based on my own intuition
	# s: 10 -> or, 11 -> or.b
	bin_format = '1100ss00iiiiiiii'
	name = 'or'

	def fetch_operands(self):
		# Get #imm value
		imm_vv = int(self.data['i'], 2)
		src = imm_vv
		# Fetch the register
		r0_vv = self.get('r0', REGISTER_TYPE)
		if self.data['s'] == '10':
			dst = r0_vv
		elif self.data['s'] == '11':
			# Fetch the register
			gbr_vv = self.get('gbr', REGISTER_TYPE)
			adr = gbr_vv + r0_vv
			# Load byte from memory
			adr_val = self.load(adr, BYTE_TYPE)
			dst = adr_val
		self.commit_func = lambda v: self.store(v, dst) if self.data['s'] == '10'\
													else self.put(v, dst)
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '10' else self.name + '.b'
		return self.addr. self.name, ['#imm', 'R0' if self.data['s'] == '10' else '@(R0, GBR)']

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		# R0 | (0x000000FF & (long)#imm)
		ret = src | dst
		return ret


class Instruction_AND(SH4Instruction):
	bin_format = '0010nnnnmmmm1001'
	name = 'and'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src , dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		ret = src & dst
		return ret


class Instruction_AND_imm(SH4Instruction):
	# I defined this based on my own intuition
	# s: 10 -> and, 11 -> and.b
	bin_format = '1100ss00iiiiiiii'
	name = 'and'

	def fetch_operands(self):
		# Get #imm value
		imm_vv = int(self.data['i'], 2)
		src = imm_vv
		# Fetch the register
		r0_vv = self.get('r0', REGISTER_TYPE)
		if self.data['s'] == '10':
			dst = r0_vv
		elif self.data['s'] == '11':
			# Fetch the register
			gbr_vv = self.get('gbr', REGISTER_TYPE)
			adr = gbr_vv + r0_vv
			# Load byte from memory
			adr_val = self.load(adr, BYTE_TYPE)
			dst = adr_val
		self.commit_func = lambda v: self.store(v, dst) if self.data['s'] == '10'\
													else self.put(v, dst)
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '10' else self.name + '.b'
		return self.addr. self.name, ['#imm', 'R0' if self.data['s'] == '10' else '@(R0, GBR)']

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		# R0 & (0x000000FF & (long)#imm)
		ret = src & dst
		return ret

class Instruction_SUB(SH4Instruction):
	# I defined this based on my intuition
	# s: 00 -> sub, 10 -> subc, 11 -> subv
	bin_format = '0011nnnnmmmm10ss'
	name = 'sub'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '00' else self.name + 'c' \
								if self.data['s'] == '10' else self.name + 'v'
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src , dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		if self.data['s'] == '00' or self.data['s'] == '11':
			ret = src - dst
		elif self.data['s'] == '10':
			tmp1 = dst - src
			tmp0 = dst
			ret = tmp1 - self.cast_to(self.get_carry(), REGISTER_TYPE)
		return ret

	# Borrow bit resulting from the operation reflecting in T-bit
	def carry(self, src, dst, ret):
		if self.data['s'] == '00':
			return
		# Rn - Rm - T -> Rn, borrow -> T
		elif self.data['s'] == '10':
			tmp1 = dst - src
			tmp0 = dst
			return True if tmp1 > tmp0 or ret > tmp1 else False
		# Rn - Rm -> Rn, underflow -> T
		elif self.data['s'] == '11':
			src_f = 0 if src >= 0 else 1
			dst_f = 0 if dst >= 0 else 1
			src_f += dst_f
			dst -= src
			ans_f = 0 if dst >= 0 else 1
			ans_f += dst_f
			return True if src_f == 1 and ans_f == 1 else False
			
class Instruction_MUL(SH4Instruction):
	# I defined this based on my intuition
	# 00|00|nnnnmmmm|01|11 mul.l Rm,Rn
	# 00|10|nnnnmmmm|11|11 muls.w Rm,Rn
	# 00|10|nnnnmmmm|11|10 mulu.w Rm,Rn
	# s: 11 -> signed, s: 10 -> unsigned
	bin_format = '00c0nnnnmmmmb11s'
	name = 'mul'

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		# signed
		if self.data['s'] == '1':
			if self.data['c'] == '0' and self.data['b'] == '0':
				src = self.get(src_name, REGISTER_TYPE)
				dst = self.get(dst_name, REGISTER_TYPE)
			elif self.data['c'] == '1' and self.data['b'] == '1':
				src = self.cast_to(self.get(src_name, WORD_TYPE), WORD_TYPE, signed=True)
				dst = self.cast_to(self.get(dst_name, WORD_TYPE), WORD_TYPE, signed=True)
		# unsigned
		elif self.data['s'] == '0':
			src = self.get(src_name, WORD_TYPE)
			dst = self.get(dst_name, WORD_TYPE)
		self.commit_result = lambda v: self.put(v, 'macl')
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '0' else self.name + 'c' \
								if self.data['s'] == '0' else self.name + 'v'
		src, dst = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src , dst]

	def compute_result2(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		if self.data['s'] == '1':
			if self.data['c'] == '0' and self.data['b'] == '0':
				mul_vv_64 = src * dst
				# mul_vv_32 = self.op_narrow_int(mul_vv_64, WORD_TYPE)
				mul_vv_32 = mul_vv_64.narrow_low(WORD_TYPE)
				ret = mul_vv_32
			else:
				ret = src * dst
		return ret

'''
		
"""		
		
class Instruction_CMP_Rm_Rn(SH4Instruction):
	'''
	cmp/eq Rm,Rn -> 0011nnnnmmmm0000
	cmp/hs Rm,Rn -> 0011nnnnmmmm0010 >= unsigned
	cmp/ge Rm,Rn -> 0011nnnnmmmm0011 >= signed
	cmp/hi Rm,Rn -> 0011nnnnmmmm0110 >  unsigned
	cmp/gt Rm,Rn -> 0011nnnnmmmm0111 >  signed
	'''
	bin_format = '0011nnnnmmmmggss'
	name = 'cmp/'
	def compute_result2(self, src, dst):
		# s -> 00 (eq), s -> 01 (signed), s -> 11 (unsigned)
		# g -> >= (ge), g -> > (g)
		sign = self.data['s']
		greq = self.data['g']
		dst_num = int(self.data['n'], 2)
		src_num = int(self.data['m'], 2)
		dst = self.get(dst_num, REGISTER_TYPE)
		src = self.get(src_num, REGISTER_TYPE)
		# cmp/eq
		if sign == '00' and greq == '00':
			self.setsrc == dst
		# MOV.X @Rm+, Rn
		elif adr_mode == '01' and const == '01':
			# Fetch the register
			reg_vv = self.get(src_num, REGISTER_TYPE)
			# Compute type
			ty = Type.int_8 if self.data['s'] == '00' \
							else  Type.int_16 if self.data['s'] == '01' \
							else Type.int_32
			# Post-increment
			if dst_num == src_num:
				reg_vv += get_type_size(ty)/8
			else:
				reg_vv = src
			self.put(reg_vv, src_num)
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		return src
	def disassemble(self):
		# greater or equal
		if self.data['g'] == '00':
			if self.data['s'] == '00':
				self.name = self.name + 'eq'
			elif self.data['s'] == '10':
				self.name = self.name + 'hs'
			elif self.data['s'] == '11':
				self.name = self.name + 'ge'
		# greater
		elif self.data['g'] == '01':
			if self.data['s'] == '10':
				self.name = self.name + 'hi'
			elif self.data['s'] == '11':
				self.name = self.name + 'gt'
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr, self.name, [src_name, dst_name]

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		return src, dst

	# decide on the value of T-bit in SR reg
	def carry(self, src, dst, ret):
		
		# Adam 
		#if src == dst:
		pass

class Instruction_CMP_Rm_Rn(SH4Instruction):
	'''
	cmp/eq Rm,Rn -> 0011nnnnmmmm0000
	cmp/hs Rm,Rn -> 0011nnnnmmmm0010 >= unsigned
	cmp/ge Rm,Rn -> 0011nnnnmmmm0011 >= signed
	cmp/hi Rm,Rn -> 0011nnnnmmmm0110 >  unsigned
	cmp/gt Rm,Rn -> 0011nnnnmmmm0111 >  signed
	'''
	bin_format = '0011nnnnmmmmggss'
	name = 'cmp/'
	def compute_result2(self, src, dst):
		# s -> 00 (eq), s -> 01 (signed), s -> 11 (unsigned)
		# g -> >= (ge), g -> > (g)
		sign = self.data['s']
		greq = self.data['g']
		dst_num = int(self.data['n'], 2)
		src_num = int(self.data['m'], 2)
		dst = self.get(dst_num, REGISTER_TYPE)
		src = self.get(src_num, REGISTER_TYPE)
		# cmp/eq
		if sign == '00' and greq == '00':
			self.setsrc == dst
		# MOV.X @Rm+, Rn
		elif adr_mode == '01' and const == '01':
			# Fetch the register
			reg_vv = self.get(src_num, REGISTER_TYPE)
			# Compute type
			ty = Type.int_8 if self.data['s'] == '00' \
							else  Type.int_16 if self.data['s'] == '01' \
							else Type.int_32
			# Post-increment
			if dst_num == src_num:
				reg_vv += get_type_size(ty)/8
			else:
				reg_vv = src
			self.put(reg_vv, src_num)
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		return src
	def disassemble(self):
		# greater or equal
		if self.data['g'] == '00':
			if self.data['s'] == '00':
				self.name = self.name + 'eq'
			elif self.data['s'] == '10':
				self.name = self.name + 'hs'
			elif self.data['s'] == '11':
				self.name = self.name + 'ge'
		# greater
		elif self.data['g'] == '01':
			if self.data['s'] == '10':
				self.name = self.name + 'hi'
			elif self.data['s'] == '11':
				self.name = self.name + 'gt'
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		return self.addr, self.name, [src_name, dst_name]

	def fetch_operands(self):
		src_name, dst_name = self.resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		return src, dst

	# decide on the value of T-bit in SR reg
	def carry(self, src, dst, ret):
		#if src == dst:
		# Adam
		pass
"""
