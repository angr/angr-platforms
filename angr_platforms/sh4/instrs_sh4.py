import abc
from arch_sh4 import ArchSH4
from pyvex.lift.util import *
from pyvex.const import get_type_size
import bitstring
from bitstring import Bits
import logging
l = logging.getLogger(__name__)

REGISTER_TYPE = Type.int_32
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

	# AO - Added args
	def __init__(self, bitstrm, arch, addr):
		super(SH4Instruction, self).__init__(bitstrm, arch, addr)
		#print(self)

	# Default flag handling
	def carry(self, *args):
		return None

	# Some common stuff we use around

	def get_sr(self):
		return self.get(STATUS_REG_IND, REGISTER_TYPE)

	def get_pc(self):
		return self.get('pc', REGISTER_TYPE)

	def put_sr(self, val):
		return self.put(val, STATUS_REG_IND)

	def get_carry(self):
		return self.get_sr()[CARRY_BIT_IND]

	def commit_result(self, res):
		if self.commit_func != None:
			self.commit_func(res)

	def compute_flags(self, *args):
		"""
		Compute the flags touched by each instruction
		and store them in the status register
		"""
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

	@abc.abstractmethod
	def fetch_operands(self):
		pass
		
	##############################################		
	# Adam's Code		
	# Based on instrs in: http://www.shared-ptr.com/sh_insns.html
	##############################################	
	
	"""
	Set system flags
	"""
	def set_flags(self, **kwargs):
	
		# TODO! - probably hook in to one of the methods above
		pass
		
	"""
	Set system flags
	"""
	def get_flag(self, flag):
	
		# TODO!
		pass
		
	"""
	Increment the PC by 2, which is what most instructions do
	"""
	def inc_pc(self):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		
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
	def get_rreg_val(self, letter, ty = Type.int_32, extend = False):
		val = self.get(self.get_rreg(letter), ty)
		
		if extend:
			val.widen_signed(ty)
			
		return val
		
	"""
	get referenced immediate value
	Gets the VexValue of the immediate value referenced by the specified letter in the instruction's bin_format
	"""
	def get_rimm_val(self, letter, ty = Type.int_32, extend = False):
		val = self.constant(int(self.data[letter], 2), ty)
		
		if extend:
			val.widen_signed(ty)
			
		return val
		
	"""
	get register value
	Gets the VexValue of the register with the specified name
	"""
	def get_reg_val(self, regname, ty = Type.int_32, extend = False):
		val = self.get(regname, ty)
		
		if extend:
			val.widen_signed(ty)
			
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

	def compute_result(self, rm, rn, rn_name):
	
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

	def compute_result(self, rm, rn, rn_name):
		"""
		Extracts the middle 32 bits from the 64-bit contents of linked general registers Rm and Rn, and stores the result in Rn. 
		"""
	
		res = ((rm << 16) & 0xFFFF0000) | ((rn >> 16) & 0x0000FFFF) 
		
		self.put(res, rn_name)
	
		self.inc_pc()
	
		return res	

class Instruction_MOVL(SH4Instruction):

	bin_format = '1101nnnndddddddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', Type.int_32, extend=True)
		rn_name = self.get_rreg('n')

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result(self, pc, d, rn_name):
		"""
		Stores immediate data, sign-extended to longword, in general register Rn. The data is stored from memory address (PC + 4 + displacement * 4). The 8-bit displacement is multiplied by four after zero-extension, and so the relative distance from the operand is in the range up to PC + 4 + 1020 bytes. The PC value is the address of this instruction. A value with the lower 2 bits adjusted to 00 is used in address calculation. 
		"""
		
		disp = (0x000000FF & d);
		toRead = ( (pc & 0xFFFFFFFC) + 4 + (disp << 2) );
		
		val = self.load(toRead, Type.int_32)
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val		

class Instruction_MOVW(SH4Instruction):

	bin_format = '1001nnnndddddddd'
	name='mov.w'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', ty=Type.int_32,extend=True)
		rn_name = self.get_rreg('n')

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result(self, pc, d, rn_name):
		"""
		Stores immediate data, sign-extended to longword, in general register Rn. The data is stored from memory address (PC + 4 + displacement * 2). The 8-bit displacement is multiplied by two after zero-extension, and so the relative distance from the table is in the range up to PC + 4 + 510 bytes. The PC value is the address of this instruction. 
		"""
		
		disp = (0x000000FF & d);
		toRead = ( pc + 4 + (disp << 1) );
		
		val = self.load(toRead, Type.int_16)
		
		if (val & 0x8000) == 0:
			val = val & 0x0000FFFF
		else:
			val = val | 0xFFFF0000
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val			

class Instruction_MOVA(SH4Instruction):

	bin_format = '11000111dddddddd'
	name='mova'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', extend=True)
		rn_name = 'r0'

		return pc, d, rn_name
		
	def disassemble(self):
	
		pc, d, rn_name = self.fetch_operands()
			
		return "%s @(%s,%s),%s" % (self.name, d, pc, rn_name)

	def compute_result(self, pc, d, rn_name):
		"""
		Stores the effective address of the source operand into general register R0. The 8-bit displacement is zero-extended and quadrupled. Consequently, the relative interval from the operand is PC + 1020 bytes. The PC is the address four bytes after this instruction, but the lowest two bits of the PC are fixed at 00.
		"""
		
		disp = (0x000000FF & d);
		
		val = ( (pc & 0xFFFFFFFC) + 4 + (disp << 2) );
				
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val			
		
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

	def compute_result(self, mach, rn_name):
		"""
		Stores system register MACH in the destination. 
		"""
				
		self.put(mach, rn_name)
	
		self.inc_pc()
	
		return mach	
		
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

	def compute_result(self, macl, rn_name):
		"""
		Stores system register MACL in the destination. 
		"""
				
		self.put(macl, rn_name)
	
		self.inc_pc()
	
		return macl	
		
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

	def compute_result(self, pr, rn_name):
		"""
		Stores system register PR in the destination. 
		"""
				
		self.put(pr, rn_name)
	
		self.inc_pc()
	
		return pr	
		
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

	def compute_result(self, mach, rn_name):
		"""
		Stores system register MACH in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(mach, rn)
					
		self.inc_pc()
	
		return mach			

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

	def compute_result(self, macl, rn_name):
		"""
		Stores system register MACL in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(macl, rn)
					
		self.inc_pc()
	
		return macl			

class Instruction_STSL_PR(SH4Instruction):

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

	def compute_result(self, pr, rn, rn_name):
		"""
		Stores system register pr in the destination. 
		"""
		
		rn -= 4
		
		self.put(rn, rn_name)
		
		self.store(pr, rn)
					
		self.inc_pc()
	
		return pr	
		
class Instruction_CLRMAC(SH4Instruction):

	bin_format = '0000000000101000'
	name='clrmac'
	
	def fetch_operands(self):								
		pass
		
	def disassemble(self):
		return self.name

	def compute_result(self):
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
		pass
		
	def disassemble(self):
		return self.name

	def compute_result(self):
		"""
		Clears the S bit
		"""
		
		self.set_flags(S=0)
							
		self.inc_pc()

class Instruction_CLRT(SH4Instruction):

	bin_format = '0000000000001000'
	name='clrt'
	
	def fetch_operands(self):								
		pass
		
	def disassemble(self):
		return self.name

	def compute_result(self):
		"""
		Clears the T bit
		"""
		
		self.set_flags(T=0)
							
		self.inc_pc()
		
class Instruction_NOP(SH4Instruction):

	bin_format = '0000000000001001'
	name='nop'
	
	def fetch_operands(self):	
		# Lol?
		return []
		
	def disassemble(self):
		return self.name

	def compute_result(self):
		"""
		No operation
		"""
									
		self.inc_pc()
		
		
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

	def compute_result(self, rn, rm, rn_name, rm_name):
		"""
		Adds together the contents of general registers Rn and Rm and stores the result in Rn. 
		"""
		
		val = rn + rm
		
		self.put(val, rn_name)
	
		self.inc_pc()
	
		return val	

class Instruction_ADD_IMM(SH4Instruction):

	bin_format = '0111nnnniiiiiiii'
	name='add'
	
	def fetch_operands(self):
			
		rn_name = self.get_rreg('n')
		i = self.get_rimm_val('i', ty=Type.int_32,extend=True)
		
		return i, rn_name
		
	def disassemble(self):
	
		i, rn_name = self.fetch_operands()
			
		return "%s #%s,%s" % (self.name, i, rn_name)

	def compute_result(self, i, rn_name):
		"""
		Adds together the contents of general registers Rn and Rm and the T bit, and stores the result in Rn. A carry resulting from the operation is reflected in the T bit. This instruction can be used to implement additions exceeding 32 bits. 
		"""
		
		if (i & 0x80) == 0:
			val = (0x000000FF & i)
		else:
			val = (0xFFFFFF00 | i)
		
		
		self.put(val, rn_name)
	
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

	def compute_result(self, T, rm, rm_name, rn, rn_name):
		"""
		Adds together the contents of general registers Rn and Rm and the T bit, and stores the result in Rn. A carry resulting from the operation is reflected in the T bit. This instruction can be used to implement additions exceeding 32 bits. 
		"""
		
		tmp1 = rn + rm
		tmp0 = rn
		
		val = tmp1 + T
		
		self.put(tmp1, rn_name)
		
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

	def compute_result(self, rm, rm_name, rn, rn_name):
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
		
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d')
		
		return pc, d
		
	def disassemble(self):
	
		pc, d = self.fetch_operands()
			
		return "%s PC+4+%s" % (self.name, d * 2)

	def compute_result(self, pc, d):
		"""
		This is an unconditional branch instruction. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BRA instruction address. As the 12-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -4096 to +4094 bytes from the BRA instruction. If the branch destination cannot be reached, this branch can be performed with a JMP instruction.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""

		temp = pc

		if (d & 0x800) == 0:
			disp = (0x00000FFF & d)
		else:
			disp = (0xFFFFF000 | d)

		val = pc + 4 + (disp << 1)
			
		self.put(val, 'pc')

		# TODO
		# execute the next instruction first
		# self.delay_slot(temp + 2)
			
		return val			

class Instruction_BT(SH4Instruction):

	bin_format = '10001001dddddddd'
	name='bt'
	
	def fetch_operands(self):
		
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d')
		T = self.get_flag('T')
		
		return pc, d, T
		
	def disassemble(self):
	
		pc, d, T = self.fetch_operands()
			
		return "%s %s" % (self.name, d)

	def compute_result(self, pc, d, T):
		"""
		Description
		This is a conditional branch instruction that references the T bit. The branch is taken if T = 1, and not taken if T = 0. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BT instruction address. As the 8-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -256 to +254 bytes from the BT instruction.

		Note
		If the branch destination cannot be reached, the branch must be handled by using BT in combination with a BRA or JMP instruction, for example. 
		"""

		if (d & 0x80) == 0:
			disp = (0x000000FF & d)
		else:
			disp = (0xFFFFFF00 | d)

		val = pc + 4 + (disp << 1)
			
		if T == 1:
			self.put(val, 'pc')
		else:
			self.inc_pc()
		
		return val

class Instruction_BF(SH4Instruction):

	bin_format = '10001011dddddddd'
	name='bf'
	
	def fetch_operands(self):
		
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d')
		T = self.get_flag('T')
		
		return pc, d, T
		
	def disassemble(self):
	
		pc, d, T = self.fetch_operands()
			
		return "%s %s" % (self.name, d)

	def compute_result(self, pc, d, T):
		"""
		Description
		This is a conditional branch instruction that references the T bit. The branch is taken if T = 0, and not taken if T = 1. The branch destination is address (PC + 4 + displacement * 2). The PC source value is the BF instruction address. As the 8-bit displacement is multiplied by two after sign-extension, the branch destination can be located in the range from -256 to +254 bytes from the BF instruction.

		Note
		If the branch destination cannot be reached, the branch must be handled by using BF in combination with a BRA or JMP instruction, for example. 
		"""

		if (d & 0x80) == 0:
			disp = (0x000000FF & d)
		else:
			disp = (0xFFFFFF00 | d)

		val = pc + 4 + (disp << 1)
			
		if T == 0:
			self.put(val, 'pc')
		else:
			self.inc_pc()
		
		return val		
		
class Instruction_JMP(SH4Instruction):

	bin_format = '0100mmmm00101011'
	name='jmp'
	
	def fetch_operands(self):
		
		rm = self.get_rreg_val('m')
		pc = self.get_reg_val('pc')
		
		return rm, pc
		
	def disassemble(self):
	
		rm, pc = self.fetch_operands()
			
		return "%s %s" % (self.name, rm)

	def compute_result(self, rm, pc):
		"""
		Unconditionally makes a delayed branch to the address specified by Rm.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""

		temp = pc

		val = rm
			
		self.put(val, 'pc')

		# TODO
		# execute the next instruction first
		# self.delay_slot(temp + 2)
			
		return val

class Instruction_JSR(SH4Instruction):

	bin_format = '0100mmmm00001011'
	name='jsr'
	
	def fetch_operands(self):
		
		rm = self.get_rreg_val('m')
		pc = self.get_reg_val('pc')
		
		return rm, pc
		
	def disassemble(self):
	
		rm, pc = self.fetch_operands()
			
		return "%s %s" % (self.name, rm)

	def compute_result(self, rm, pc):
		"""
		Description
		Makes a delayed branch to the subroutine procedure at the specified address after execution of the following instruction. Return address (PC + 4) is saved in PR, and a branch is made to the address indicated by general register Rm. JSR is used in combination with RTS for subroutine procedure calls.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 
		"""

		temp = pc

		val = rm
			
		self.put(val, 'pc')
		self.put(pc + 4, 'pr')

		# TODO
		# execute the next instruction first
		# self.delay_slot(temp + 2)
			
		return val				

class Instruction_RTS(SH4Instruction):

	bin_format = '0000000000001011'
	name='rts'
	
	def fetch_operands(self):
		
		pr = self.get_reg_val('pr')
		pc = self.get_reg_val('pc')
		
		return pr, pc
		
	def disassemble(self):
				
		return self.name

	def compute_result(self, pr, pc):
		"""
		Description
		Returns from a subroutine procedure by restoring the PC from PR. Processing continues from the address indicated by the restored PC value. This instruction can be used to return from a subroutine procedure called by a BSR or JSR instruction to the source of the call.

		Note
		As this is a delayed branch instruction, the instruction following this instruction is executed before the branch destination instruction. 		
		"""

		temp = pc

		val = pr
			
		self.put(val, 'pc')

		# TODO
		# execute the next instruction first
		# self.delay_slot(temp + 2)
			
		return val				

		
##############################################		
# End Adam's Code		
##############################################		
		
class Instruction_MOV_Rm_Rn(SH4Instruction):
	# I defined this based on my intuition
	# a: 01 -> @Rm, Rn # 00 -> Rm, @Rn
	# s: 00 -> mov.b, 01 -> mov.w, 10 -> mov.l, 11 -> mov
	bin_format = '0a10nnnnmmmm0css'
	name = 'mov'

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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

	def compute_result(self, src, dst):
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
	def compute_result(self, src, dst):
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
	def compute_result(self, src, dst):
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

