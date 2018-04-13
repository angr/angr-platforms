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
	##############################################	
		
	"""
	Increment the PC by 2, which is what most instructions do
	"""
	def inc_pc(self):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		
	"""
	Gets the name of the register referenced by the specified letter
	in the instruction's bin_format
	"""
	def get_rreg(self, letter):
		return self.resolve_one_reg(int(self.data[letter], 2))
			
	"""
	Gets the VexValue of the register referenced by the specified letter
	in the instruction's bin_format
	"""
	def get_rreg_val(self, letter, ty = Type.int_32):
		return self.get(self.get_rreg(letter), ty)
		
	"""
	Gets the VexValue of the immediate value referenced by the specified letter in the instruction's bin_format
	"""
	def get_rimm_val(self, letter, ty = Type.int_32, extend = False):
		val = self.constant(int(self.data[letter], 2), ty)
		
		if extend:
			val.widen_signed(ty)
			
		return val
		
	"""
	Gets the VexValue of the register with the specified name
	"""
	def get_reg_val(self, regname, ty = Type.int_32):
		return self.get(regname, ty)
			
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
		
"""
Handle xtrct
"""
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

"""
Handle mov.l
"""
class Instruction_MOVL(SH4Instruction):

	bin_format = '1101nnnndddddddd'
	name='mov.l'
	
	def fetch_operands(self):
									
		pc = self.get_reg_val('pc')
		d = self.get_rimm_val('d', extend=True)
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

##############################################		
# End Adam's Code		
##############################################		
		
class Instruction_MOV_Rm_Rn(SH4Instruction):
	# I defined this based on my intuition
	# a: 01 -> @Rm, Rn # 00 -> Rm, @Rn
	# s: 00 -> mov.b, 01 -> mov.w, 10 -> mov.l, 11 -> mov
	bin_format = 'aa10nnnnmmmm0css'
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
		elif adr_mode == '01' and const == '1':
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
		if adr_mode == '01':
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
		elif adr_mode == '00':
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		src, dst = resolve_reg(self.data['m'], self.data['n'])
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		src, dst = resolve_reg(self.data['m'], self.data['n'])
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
		src = self.get(src_name, REGISTER_TYPE)
		dst = self.get(dst_name, REGISTER_TYPE)
		self.commit_result = lambda v: self.put(v, dst_name)
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '00' else self.name + 'c' \
								if self.data['s'] == '10' else self.name + 'v'
		src, dst = resolve_reg(self.data['m'], self.data['n'])
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
	bin_format = '00ccnnnnmmmmbbss'
	name = 'mul'

	def fetch_operands(self):
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
		# signed
		if self.data['s'] == '11':
			if self.data['c'] == '00' and self.data['b'] == '01':
				src = self.get(src_name, REGISTER_TYPE)
				dst = self.get(dst_name, REGISTER_TYPE)
			elif self.data['c'] == '10' and self.data['b'] == '11':
				src = self.cast_to(self.get(src_name, WORD_TYPE), WORD_TYPE, signed=True)
				dst = self.cast_to(self.get(dst_name, WORD_TYPE), WORD_TYPE, signed=True)
		# unsigned
		elif self.data['s'] == '10':
			src = self.get(src_name, WORD_TYPE)
			dst = self.get(dst_name, WORD_TYPE)
		self.commit_result = lambda v: self.put(v, 'macl')
		return src, dst

	def disassemle(self):
		self.name = self.name if self.data['s'] == '00' else self.name + 'c' \
								if self.data['s'] == '10' else self.name + 'v'
		src, dst = resolve_reg(self.data['m'], self.data['n'])
		return self.addr. self.name, [src , dst]

	def compute_result(self, src, dst):
		pc_vv = self.get_pc()
		pc_vv += 2
		self.put(pc_vv, 'pc')
		if self.data['s'] == '11':
			if self.data['c'] == '00' and self.data['b'] == '01':
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
		src_name, dst_name = resolve_reg(self.data['m'], self.data['n'])
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

