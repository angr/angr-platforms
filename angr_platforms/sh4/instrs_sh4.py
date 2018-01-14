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
# s: operand size
# c: constant post/pre increment

# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return Bits(bin=s).int

class SH4Instruction(Instruction):

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
        if self.commit_func:
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
##
## MSP430 does not have instruction "types" but for sake of simplicity I have classified them
## based on the functionality and corresponding bit orders
## These define the formats, and number of arguments.
## Here are the classes for those:
##

class Instruction_MOV_Rm_Rn(SH4Instruction):
    # I defined this based on my intuition
    # a: 01 -> @Rm, Rn # 00 -> Rm, @Rn
    # s: 00 -> mov.b, 01 -> mov.w, 10 -> mov.l, 11 -> mov
    bin_format = 'aa10nnnnmmmmccss'
    name = 'mov'

    def compute_result(self, src, dst):
        adr_mode = self.data['a']
        const = self.data['c']
        dst_num = int(self.data['n'], 2)
        src_num = int(self.data['m'], 2)
        # MOV.X Rm, @-Rn
        if adr_mode == '00' and const == '01':
            self.put(dst, dst_num)
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
        if self.data['s'] == '00':
            self.name = self.name + ".b"
        elif self.data['s'] == '01':
            self.name + ".w"
        elif self.data['s'] == '10':
            self.name + ".l"
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
            if const == '00':
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
            elif const == '01':
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
            if const == '00':
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
            elif const == '01':
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
        return ret if self.data['s'] == '10' else self.op_narrow_int(ret, BYTE_TYPE)


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
    bin_format = ''
    name = 'sub'

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


class Instruction_RRC(Type1Instruction):
    # Rotate Right logical with carry-in.
    opcode = "000"
    name = 'rrc'

    def compute_result(self, src):
        # Get carry-in
        carryin = self.get_carry()
        # Do it
        src >>= 1
        # Put the carry-in in the right place
        if self.data['b'] == '1':
            src[7] = carryin
        else:
            src[15] = carryin
        # Write it out
        return src

    def carry(self, src, retval):
        return src[0]


class Instruction_SWPB(Type1Instruction):
    # Swap byte halves.  No B/W forms.
    opcode = '001'
    name = 'swpb'

    def compute_result(self, src):
        low_half = src.cast_to(Type.int_8).cast_to(Type.int_16) << self.constant(8, Type.int_8) # FIXME: TODO:
        high_half = src >> 8
        return high_half | low_half


class Instruction_RRA(Type1Instruction):
    # Rotate Right Arithmetic.  Right shift with sign-extend.
    opcode = "010"
    name = 'rra'

    def compute_result(self, src, writeout):
        # Do it
        src >>= 1
        # A shitty sign-extend
        if self.data['b'] == '1':
            src[7] = src[6]
        else:
            src[15] = src[14]
        return src

    def carry(self, src, ret):
        return src[0]


class Instruction_SXT(Type1Instruction):
    # Sign extend 8 to 16 bits.
    # No b/w form.
    opcode = '011'
    name = 'sxt'

    def compute_result(self, src):
        return src.cast_to(Type.int_16, signed=True)


class Instruction_PUSH(Type1Instruction):
    # Push src onto the stack.
    opcode = '100'
    name = 'push'

    def compute_result(self, src):
        # Decrement SP
        sp = self.get(1, REGISTER_TYPE)
        sp -= 2
        # Store src at SP
        self.store(src, sp)
        # Store SP.  No write-out.
        self.put(sp, 'sp')

    # No flags.
    def negative(self, src, ret):
        pass

    def zero(self, src, ret):
        pass


class Instruction_CALL(Type1Instruction):
    opcode = '101'
    name = 'call'
    # Call src.  Pushes PC. No flags.

    def compute_result(self, src):
        # Push the next instruction's address
        pc = self.get_pc() + self.bytewidth
        sp = self.get('sp', Type.int_16)
        sp = sp - 2
        self.store(pc, sp)
        self.put(sp, 'sp')
        # This ends the BB, update the IRSB
        self.jump(None, src, jumpkind=JumpKind.Call)

    def negative(self, src, ret):
        pass

    def zero(self, src, ret):
        pass


class Instruction_RETI(Type1Instruction):
    # Return *from interrupt*
    # Pop SR AND PC.
    opcode = '110'
    name = 'reti'

    def disassemble(self):
        return self.addr, self.name, []

    def compute_result(self, src):
        # Pop the saved SR
        import ipdb; ipdb.set_trace(context=30)
        sp = self.get(1, REGISTER_TYPE)
        sr = self.get_sr()
        sp += 2
        # Pop the saved PC
        newpc = self.load(sp, Type.int_16)
        sp += 2
        # Store the popped values
        self.put_sr(sr)
        # Jump to PC (setting the jumpkind)
        self.jump(None, newpc, jumpkind=JumpKind.Ret)

    def negative(self, ret):
        pass

    def zero(self, ret):
        pass

##
## Two operand instructions.
##


class Instruction_MOV(Type3Instruction):
    # Boring move.  No flags.
    opcode = '0100'
    name = 'mov'

    def fetch_operands(self):
        if self.data['s'] == '0001' and self.data['d'] == '0000':
            return None, None
        else:
            return Type3Instruction.fetch_operands(self)

    def disassemble(self):
        # support useful pseudo-ops for disassembly
        addr, name, args = Type3Instruction.disassemble(self)
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                return addr, 'ret', []
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                return addr, 'br', [args[0]]
        else:
            return addr, name, args

    def compute_result(self, src, dst):
        # HACK: In MSP430, a MOV to R0 from SP is a RET.
        # VEX would like it very much if you set the jumpkind.
        if self.data['d'] == '0000':
            if self.data['s'] == '0001':
                sp = self.get('sp', REGISTER_TYPE)
                newpc = self.load(sp, REGISTER_TYPE)
                sp = sp + 2
                self.put(sp, 'sp')
                self.jump(None, newpc, jumpkind=JumpKind.Ret)
            else:
                # If we're setting PC, but not from SP+, it's a BR instead
                self.jump(None, self.constant(self.addr, REGISTER_TYPE))
        return src

    def negative(self, src, dst, ret):
        pass

    def zero(self, src, dst, ret):
        pass


class Instruction_ADD(Type3Instruction):
    # Add src + dst, set carry
    opcode = '0101'
    name = 'add'

    def compute_result(self, src, dst):
        return src + dst

    def compute_flags(self, src, dst, ret):
        # The flags for this are super ugly.
        if self.data['b'] == '0':
            src17 = src.cast_to(Type.int_17)
            dst17 = dst.cast_to(Type.int_17)
            ret17 = src17 + dst17
            c = ret17[16]
            o = (ret17[15] ^ src17[15]) & (ret17[15] ^ dst17[15])
            retval = ret17
        else:
            src9 = src.cast_to(Type.int_9)
            dst9 = dst.cast_to(Type.int_9)
            ret9 = src9 + dst9
            c = ret9[8]
            o = ((ret9[7] ^ src9[7]) & (ret9[7] ^ dst9[7])).cast_to(Type.int_1)
            retval = ret9
        z = self.zero(src, dst, retval)
        n = self.negative(src, dst, retval)
        self.set_flags(z, n, c, o)


class Instruction_ADDC(Type3Instruction):
    # dst = src + dst + C
    opcode = '0110'
    name = 'addc'

    def compute_result(self, src, dst):
        return src + dst + self.carry()

    def compute_flags(self, src, dst, retval):
        carryin = self.get_carry()
        if self.data['b'] == '0':
            src17 = src.cast_to(Type.int_17)
            dst17 = dst.cast_to(Type.int_17)
            ci17 = carryin.cast_to(Type.int_17)
            ret17 = src17 + dst17 + ci17
            c = ret17[16]
            o = ((ret17[15] ^ src17[15]) & (ret17[15] ^ dst17[15])).cast_to(Type.int_16)
            retval = ret17
        else:  # self.data['b'] == '1':
            src9 = src.cast_to(Type.int_9)
            dst9 = dst.cast_to(Type.int_9)
            ret9 = src9 + dst9
            c = ret9[8]
            o = ((ret9[7] ^ src9[7]) & (ret9[7] ^ dst9[7])).cast_to(Type.int_16)
            retva= ret9
        z = self.zero(src, dst, retval)
        n = self.negative(src, dst, retval)
        self.set_flags(z, n, c, o)


class Instruction_SUBC(Type3Instruction):
    opcode = '0111'
    name = 'subc'

    def compute_result(self, src, dst):
        return src - dst + self.get_carry()

    def overflow(self, src, dst, ret):
        # TODO: This is probably wrong
        if self.data['b'] == '0':
            return (ret[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (ret[7] ^ src[7]) & (ret[7] ^ dst[7])

    def carry(self, src, dst, ret):
        return dst > (src + self.get_carry())


class Instruction_SUB(Type3Instruction):
    opcode = '1000'
    name = "sub"

    def compute_result(self, src, dst):
        return dst - src

    def overflow(self, src, dst, ret):
        # TODO: This is probably wrong
        if self.data['b'] == '0':
            return (ret[15] ^ src[15]) & (ret[15] ^ dst[15])
        else:
            return (ret[7] ^ src[7]) & (ret[7] ^ dst[7])

    def carry(self, src, dst, ret):
        return dst > src


class Instruction_CMP(Instruction_SUB):
    opcode = '1001'
    name = 'cmp'

    def commit_result(self, res):
        pass


class Instruction_DADD(Type3Instruction):
    opcode = '1010'
    name = 'dadd'

    def compute_result(self, src, dst):
        # Ya know... fuck this...
        srcs = []
        dsts = []
        bits = 8 if self.data['b'] == '1' else 16
        ret = self.constant(0, BYTE_TYPE if self.data['b'] == '1' else REGISTER_TYPE)
        for x in range(0, bits, 4):
            srcs += src[x:x+3]
            dsts += dst[x:x+3]
        carry = self.get_carry()
        rets = []
        for s, d in zip(srcs, dsts):
            r = s + d + carry
            carry = r / 10
            r %= 10
            rets += r
        self.carry = carry #Carry computed in-line. save it.
        # Smash the digits back together
        for r, x in zip(rets, range(0, bits, 4)):
                ret | (r << x).cast_to(Type.int_16)
        return ret

    def carry(self, src, dst, ret):
        return self.carry

    def overflow(self, src, dst, ret):
        return None # WTF: Docs say this is actually undefined!?


class Instruction_BIC(Type3Instruction):
    # Bit Clear.  dst = ~src & dst
    opcode = '1100'
    name = 'bic'

    def compute_result(self, src, dst):
        return ~src & dst

    def negative(self, src, dst, ret):
        pass

    def zero(self, src, dst, ret):
        pass


class Instruction_BIS(Type3Instruction):
    # Bit Set.  Normal people call this "or"
    opcode = '1101'
    name = 'bis'

    def compute_result(self, src, dst):
        return src | dst


class Instruction_BIT(Type3Instruction):
    # Bit Test. Just update flags.  No write-out
    opcode = "1011"
    name = "bit"

    def compute_result(self, src, dst):
        return src & dst

    def zero(self, src, dst, ret):
        return self.constant(0, ret.ty)

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)


class Instruction_XOR(SH4Instruction):
    # Exclusive Or
    name = 'xor'

    def compute_result(self, src, dst):
        return src ^ dst

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)

    def overflow(self, src, dst, ret):
        if self.data['b'] == '1':
            return src[7] & dst[7]
        else:
            return src[15] & dst[15]


class Instruction_AND(Type3Instruction):
    # Logical and.
    opcode = "1111"
    name = 'and'

    def compute_result(self, src, dst):
        return src & dst

    def overflow(self, src, dst, ret):
        return self.constant(0, ret.ty)

    def carry(self, src, dst, ret):
        return ret != self.constant(0, ret.ty)

##
## Zero-operand Jumps
##


class Instruction_JNE(Type2Instruction):
    opcode = '000'
    name = 'jne'

    def compute_result(self, dst):
        self.jump(self.get_zero() == 0, dst)


class Instruction_JEQ(Type2Instruction):
    opcode = '001'
    name = 'jeq'

    def compute_result(self, dst):
        self.jump(self.get_zero() != 0, dst)


class Instruction_JNC(Type2Instruction):
    opcode = '010'
    name = 'jnc'

    def compute_result(self, dst):
        self.jump(self.get_carry() == 0, dst)


class Instruction_JC(Type2Instruction):
    opcode = '011'
    name = 'jc'

    def compute_result(self, dst):
        self.jump(self.get_carry() != 0, dst)


class Instruction_JN(Type2Instruction):
    opcode = '100'
    name = 'jn'

    def compute_result(self, dst):
        self.jump(self.get_negative() != 0, dst)


class Instruction_JGE(Type2Instruction):
    opcode = '101'
    name = 'jge'

    def compute_result(self, dst):
        self.jump(self.get_negative() == self.get_overflow(), dst)


class Instruction_JL(Type2Instruction):
    opcode = '110'
    name = 'jl'

    def compute_result(self, dst):
        self.jump(self.get_negative() == self.get_overflow(), dst)


class Instruction_JMP(Type2Instruction):
    opcode = '111'
    name = 'jl'

    def compute_result(self, dst):
        self.jump(None, dst)
