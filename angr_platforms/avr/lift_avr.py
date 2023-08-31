#pylint: disable=wildcard-import, unused-wildcard-import, unused-argument, arguments-differ
import logging
import re

import bitstring
from pyvex.expr import int_type_for_size
from pyvex.lifting import register
from pyvex.lifting.util import *

from .arch_avr import ArchAVR

# This is a lifter for Atmel AVR 8-bit microcontrollers.
# (most commonly known to the public as "that Arduino thing")
# The goal is to support everything in this document:
# http://www.atmel.com/images/Atmel-0856-AVR-Instruction-Set-Manual.pdf
#
# AVR has no real "instruction formats" to speak of, and is generally a gigantic shitshow to decode.
# I have made the best effort possible to simplify it through OneReg / TwoReg / RegImm / etc,
# but there are just so many exceptiosn that it's barely worth it.

class AVRFlagIndex:
    C_Carry = 0
    Z_Zero = 1
    N_Negative = 2
    V_TwoComplementOverflow = 3
    S_Signed = 4
    H_HalfCarry = 5
    T_TransferBit = 6
    I_Interrupt = 7

REG_TYPE = Type.int_8
DOUBLEREG_TYPE = Type.int_16


# Lots of things are going to be interpreted as signed immediates. Here's a quickie to load them
def bits_to_signed_int(s):
    return bitstring.Bits(bin=s).int

# When we need a trailer, get the trailer this way, little-endian.
def read_trailer(bitstrm):
    return bitstring.Bits(uint=bitstrm.read('uintle:16'), length=16).bin

# compute the carry bit at position i for res = dst + src
def compute_carry_add(i, src, dst, res):
    return (src[i] & dst[i]) | (src[i] & ~res[i]) |  (dst[i] & ~res[i])

# compute the carry bit at position i for res = dst - src
def compute_carry_sub(i, src, dst, res):
    return (~dst[i] & src[i]) | (src[i] & res[i]) |  (res[i] & ~dst[i])

# compute overflow bit for res = dst + src
def compute_overflow_add(src, dst, res):
    return (dst[7] & src[7] & ~res[7]) | (~dst[7] & ~src[7] & res[7])

# compute overflow bit for res = dst - src
def compute_overflow_sub(src, dst, res):
    return (dst[7] & ~src[7] & ~res[7]) | (~dst[7] & src[7] & res[7])


class AVRInstruction(Instruction):
    # TODO: allow changing this based on arch, support pc overflow
    pc_type = Type.int_24

    def lift(self, irsb_c, past_instructions, future_instructions):
        self.apply_context(past_instructions, future_instructions)
        super().lift(irsb_c, past_instructions, future_instructions)

    def apply_context(self, past, future):
        pass

    def compute_result(self, *args):
        pass

    def get_reg(self, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 5:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible registers.  See get_reg_16_31")
            return self.get(int(name, 2), REG_TYPE)
        else:
            try:
                reg, width = self.arch.registers[name]
                ty = REG_TYPE if width == 1 else DOUBLEREG_TYPE
                return self.get(reg, ty)
            except KeyError as e:
                raise ValueError("Invalid register for name: " + name) from e

    def put_reg(self, value, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 5:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible registers.  See get_reg_16_31")
            self.put(value, int(name, 2))
            return
        else:
            try:
                reg, _ = self.arch.registers[name]
                self.put(value, reg)
                return
            except KeyError as e:
                raise ValueError("Invalid register for put: " + name) from e

    def get_reg_pair(self, name_num):
        if isinstance(name_num, str) and re.match('^[01]+$', name_num):
            if len(name_num) != 4:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible double registers.")
            num = int(name_num, 2)
        else:
            num = name_num
        try:
            offset = self.arch.registers['R%d_R%d' % (2 * num + 1, 2 * num)][0]
            return self.get(offset, DOUBLEREG_TYPE)
        except KeyError as e:
            raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num)) from e

    def put_reg_pair(self, value, name_num):
        if isinstance(name_num, str) and re.match('^[01]+$', name_num):
            if len(name_num) != 4:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible double registers.")
            name_num = int(name_num, 2)
        if isinstance(name_num, int):
            num = name_num

            try:
                offset = self.arch.registers['R%d_R%d' % (2 * num + 1, 2 * num)][0]
                return self.put(value, offset)
            except KeyError as e:
                raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num)) from e
        else:
            try:
                offset = self.arch.registers[name_num][0]
                return self.put(value, offset)
            except KeyError as e:
                raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num)) from e

    def _get_ioreg_register(self, reg_offset, ty):
        # we need special handling for the stack pointer
        # angr expects the stack pointer to point to the last stack entry,
        # while the AVR stack pointer must point to the next free entry (one byte below the last stack entry)
        #
        # luckily, the only way that a program can observe the stack pointer is through IO registers,
        # so we can let the SP in the register file point to the last stack entry and translate it
        # during IO register access.
        spl = self.arch.registers["SPL"][0]
        sph = self.arch.registers["SPH"][0]

        if reg_offset == spl:
            assert ty in [Type.int_8, Type.int_16], "access to SP/SPL must be either 8 or 16 bit size"
            sp = self.get("SP", DOUBLEREG_TYPE)
            return (sp - 1).cast_to(ty)

        if reg_offset == sph:
            assert ty == Type.int_8, "access to SPH must be 8 bit size"
            sp = self.get("SP", DOUBLEREG_TYPE)
            return (sp - 1).narrow_high(Type.int_8)

        return self.get(reg_offset, ty)

    def get_ioreg(self, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 6:
                # The ISA has special restrictions on what instructions use which
                # regs.  6-bit IO regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible IO registers.")
            return self._get_ioreg_register(self.arch.ioreg_offset + int(name, 2), REG_TYPE)
        else:
            try:
                reg, width = self.arch.registers[name]
                ty = REG_TYPE if width == 1 else DOUBLEREG_TYPE
                return self._get_ioreg_register(reg, ty)
            except KeyError as e:
                raise ValueError("Invalid register for name: " + name) from e

    def _put_ioreg_register(self, value, reg_offset):
        spl = self.arch.registers["SPL"][0]
        sph = self.arch.registers["SPH"][0]

        if reg_offset == spl:
            assert value.ty in [Type.int_8, Type.int_16], "access to SP/SPL must be either 8 or 16 bit size"

            self.put_reg(value + 1, "SPL")
            return

        if reg_offset == sph:
            assert value.ty == Type.int_8, "access to SPH must be 8 bit size"
            low = self.get_reg("SPL")
            self.put_reg(value + (low == 0).ite(1, 0), "SPH")
            return

        self.put(value, reg_offset)


    def put_ioreg(self, value, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 6:
                # The ISA has special restrictions on what instructions use which
                # regs.  6-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible IO registers. ")
            self._put_ioreg_register(value, self.arch.ioreg_offset + int(name, 2))
            return
        else:
            try:
                reg, _ = self.arch.registers[name]
                self._put_ioreg_register(value, reg)
                return
            except KeyError as e:
                raise ValueError("Invalid register for put: " + name) from e

    # AVR has different address spaces for flash (program memory) and ram (data memory).
    # The program memory is mapped at arch.flash_offset. All program addresses are translated during lifting.
    def load_program(self, addr, ty):
        return self.load(addr.cast_to(Type.int_32) + self.arch.flash_offset, ty)

    def load_data(self, addr, ty):
        return self.load(addr, ty)

    def store_program(self, val, addr):
        self.store(val, addr.cast_to(Type.int_32) + self.arch.flash_offset)

    def store_data(self, val, addr):
        self.store(val, addr)

    #################################
    #      Flag access helpers      #
    #################################

    def get_flag(self, idx):
        assert 0 <= idx < 8
        flag_reg_tmp = self.get_reg('SREG')
        return flag_reg_tmp[idx]

    def set_flag(self, idx, value):
        assert 0 <= idx < 8
        flag_reg_tmp = self.get_reg('SREG')
        flag_reg_tmp[idx] = value
        self.put_reg(flag_reg_tmp, 'SREG')

    def get_carry(self):
        return self.get_flag(AVRFlagIndex.C_Carry)

    # Default flag behavior

    # pylint: disable=no-self-use
    def interrupt_enable(self, *args):
        return None

    # pylint: disable=no-self-use
    def transfer(self, *args):
        return None

    # pylint: disable=no-self-use
    def half_carry(self, *args):
        return None

    def signed(self, *args):
        v = self.overflow(*args)  # pylint: disable=assignment-from-none
        n = self.negative(*args)  # pylint: disable=assignment-from-none
        if n is not None and v is not None:
            return n ^ v
        else:
            return None

    def overflow(self, *args):
        return None

    def negative(self, *args):
        return None

    def zero(self, *args):
        if not args:
            raise Exception(repr(self))
        return args[-1] == 0

    def carry(self, *args):
        return None

    def set_flags(self, i, t, h, s, v, z, c):
        flags = [(i, AVRFlagIndex.I_Interrupt),
                 (t, AVRFlagIndex.T_TransferBit),
                 (h, AVRFlagIndex.H_HalfCarry),
                 (s, AVRFlagIndex.S_Signed),
                 (v, AVRFlagIndex.V_TwoComplementOverflow),
                 (z, AVRFlagIndex.Z_Zero),
                 (c, AVRFlagIndex.C_Carry)]
        mask = 0x0
        value = 0x0
        for flag, offset in flags:
            if isinstance(flag, int):
                flag = self.constant(flag, Type.int_8)
            if flag:
                mask |= (1 << offset)
                value |= flag.cast_to(Type.int_8) << offset
        if not mask:
            return
        sreg = self.get_reg('SREG')
        self.put_reg((sreg & ~mask) | value, 'SREG')

    def match_instruction(self, data, bitstrm):
        if hasattr(self, 'opcode'):
            if data['o'] != self.opcode:  # pylint: disable=no-member
                raise ParseError("Mismatched opcode, expected %s, got %s" % (self.opcode, data['o']))  # pylint: disable=no-member
        else:
            if 'o' in data:
                raise Exception("Instruction " + self.name + " should probably have an opcode")  # pylint: disable=no-member

    def compute_flags(self, *args):
        i = self.interrupt_enable(*args)  # pylint: disable=assignment-from-none
        t = self.transfer(*args)  # pylint: disable=assignment-from-none
        h = self.half_carry(*args)  # pylint: disable=assignment-from-none
        s = self.signed(*args)
        v = self.overflow(*args)  # pylint: disable=assignment-from-none
        z = self.zero(*args)
        c = self.carry(*args)  # pylint: disable=assignment-from-none
        self.set_flags(i, t, h, s, v, z, c)


    # PC helpers
    #
    # Note that the program counter in AVR is always 2-byte aligned.
    # So the instruction's least significant bit of the bytewise address is always 0,
    # which is why the instruction pointer must be interpreted as a 16-bitwise address.
    #
    # So if PC = 0x8, that refers to the instruction located at byte offset 0x8<<1 = 0x10

    def relative_jump(self, condition, offset, **kwargs):
        self.absolute_jump(condition, self.get_pc() + offset, **kwargs)

    def absolute_jump(self, condition, addr, **kwargs):
        if not isinstance(addr, int):
            addr = addr.cast_to(Type.int_32)
        self.jump(condition, self.arch.flash_offset + (addr << 1), **kwargs)

    def get_pc(self):
        return (self.addr - self.arch.flash_offset) >> 1
#
# Some "instruction formats".  These only get you so far in AVR.
#

class OneRegAVRInstruction(AVRInstruction):
    bin_format = '1001010dddddoooo'

    def fetch_operands(self):
        return (self.get_reg(self.data['d']), )

    def compute_result(self, src):
        pass

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class NoFlags:

    def compute_flags(self, *args):
        pass

class TwoDoubleRegAVRInstruction(AVRInstruction):
    bin_format = 'ooooooooddddrrrr'

    def fetch_operands(self):
        return (self.get_reg_pair(self.data['r']), self.get_reg_pair(self.data['d']))

    def compute_result(self, src, dst):
        pass

    def commit_result(self, res):
        self.put_reg_pair(res, self.data['d'])

class TwoRegAVRInstruction(AVRInstruction):
    bin_format = 'oooooordddddrrrr'

    def fetch_operands(self):
        src = self.get(int(self.data['r'], 2), REG_TYPE)
        dst = self.get(int(self.data['d'], 2), REG_TYPE)
        return src, dst

    def compute_result(self, src, dst):
        pass

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class DoubleRegImmAVRInstruction(AVRInstruction):
    bin_format = "ooooooooKKddKKKK"

    def fetch_operands(self):
        # K is unsigned, d is {24,26,28,30} pair
        src = self.get_reg_pair("11" + self.data['d'])
        imm = self.constant(int(self.data['K'], 2), DOUBLEREG_TYPE)
        return src, imm

    def commit_result(self, res):
        self.put_reg_pair(res, "11" + self.data["d"])

class RegImmAVRInstruction(AVRInstruction):
    bin_format = "ooooKKKKddddKKKK"

    def fetch_operands(self):
        # K is unsigned, d is {16 <= d <= 31}
        src = self.get_reg("1" + self.data['d'])
        imm = self.constant(int(self.data['K'], 2), REG_TYPE)
        return src, imm

    def compute_result(self, src, imm):
        pass

    def commit_result(self, res):
        self.put_reg(res, "1" + self.data["d"])


# ARITHMETIC INSTRUCTIONS
#
# These instructions only touch registers and flags, and do not alter control flow or memory.
# There are no complex side effects for these instructions.

class Instruction_ADC(TwoRegAVRInstruction):
    opcode = '000111'
    name = 'adc'

    def compute_result(self, src, dst):
        carryin = self.get_carry()
        return src + dst + carryin

    def carry(self, src, dst, res):
        return compute_carry_add(7, src, dst, res)

    def half_carry(self, src, dst, res):
        return compute_carry_add(3, src, dst, res)

    def overflow(self, src, dst, res):
        return compute_overflow_add(src, dst, res)

    def negative(self, src, dst, res):
        return res[7]

class Instruction_ADD(TwoRegAVRInstruction):
    opcode = '000011'
    name = 'add'

    def compute_result(self, src, dst):
        return src + dst

    def carry(self, src, dst, res):
        return compute_carry_add(7, src, dst, res)

    def half_carry(self, src, dst, res):
        return compute_carry_add(3, src, dst, res)

    def overflow(self, src, dst, res):
        return compute_overflow_add(src, dst, res)

    def negative(self, src, dst, res):
        return res[7]

class Instruction_ADIW(DoubleRegImmAVRInstruction):
    opcode = "10010110"
    name = 'adiw'

    def compute_result(self, src, imm):
        return src + imm

    def carry(self, src, dst, res):
        return src[15] & ~res[15]

    def overflow(self, src, dst, res):
        return ~src[15] & res[15]

    def negative(self, src, dst, res):
        return res[15]

class Instruction_AND(TwoRegAVRInstruction):
    opcode = '001000'
    name = 'and'

    def compute_result(self, src, dst):
        return src & dst

    def overflow(self, src, dst, res):
        return 0

    def negative(self, src, dst, res):
        return res[7]

class Instruction_ANDI(RegImmAVRInstruction):
    opcode = '0111'
    name = 'andi'

    def compute_result(self, src, imm):
        return src + imm

    def overflow(self, src, dst, res):
        return 0

    def negative(self, src, dst, res):
        return res[7]

class Instruction_ASR(OneRegAVRInstruction):
    opcode = "0101"
    name = 'asr'

    def compute_result(self, src):
        msb = src[7]
        src >>= 1
        src[7] = msb
        return src

    def carry(self, src, res):
        return src[0]

    def negative(self, src, res):
        return res[7]

    def overflow(self, src, res):
        return self.carry(src, res) ^ self.negative(src, res)

class Instruction_BCLR(NoFlags, AVRInstruction):
    bin_format = '100101001sss1000'
    name = 'bclr'

    def fetch_operands(self):
        return (int(self.data['s'], 2), )

    def compute_result(self, idx):
        sr = self.get_reg('SREG')
        sr[idx] = 0
        self.put_reg(sr, "SREG")

class Instruction_BLD(NoFlags, AVRInstruction):
    bin_format = '1111100ddddd0bbb'
    name = 'bld'

    def fetch_operands(self):
        return (int(self.data["d"], 2), int(self.data['b'], 2))

    def compute_result(self, dst, idx):
        t = self.get_flag(AVRFlagIndex.T_TransferBit)
        val = self.get(dst, REG_TYPE)
        val[idx] = t
        return val

    def commit_result(self, res):
        self.put_reg(res, self.data["d"])

class Instruction_BSET(NoFlags, AVRInstruction):
    bin_format = '100101000sss1000'
    name = 'bset'

    def fetch_operands(self):
        return (int(self.data['s'], 2), )

    def compute_result(self, idx):
        sr = self.get_reg('SREG')
        sr[idx] = 1
        self.put_reg(sr, 'SREG')

class Instruction_BST(NoFlags, AVRInstruction):
    bin_format = '1111101ddddd0bbb'
    name = 'bst'

    def fetch_operands(self):
        src = self.get_reg(self.data['d'])
        idx = int(self.data['b'], 2)
        return src, idx

    def compute_result(self, src, idx):
        self.set_flag(AVRFlagIndex.T_TransferBit, src[idx])

class Instruction_COM(OneRegAVRInstruction):
    opcode = "0000"
    name = 'com'

    def compute_result(self, src):
        return 0xFF - src

    def carry(self, src, res):
        return 1

    def negative(self, src, res):
        return res[7]

    def overflow(self, src, res):
        return 0

class Instruction_DEC(OneRegAVRInstruction):
    opcode = '1010'
    name = 'dec'

    def compute_result(self, src):
        return src - 1

    def negative(self, src, res):
        return res[7]

class Instruction_EOR(TwoRegAVRInstruction):
    opcode = '001001'
    name = 'eor'

    def compute_result(self, src, dst):
        return src ^ dst

    def overflow(self, *args):
        return 0

    def negative(self, src, dst, res):
        return res[7]

class Instruction_INC(NoFlags, OneRegAVRInstruction):
    opcode = '0011'
    name = 'inc'

    def compute_result(self, src):
        return src + 1

class Instruction_LDI(NoFlags, RegImmAVRInstruction):
    opcode = '1110'
    name = 'ldi'

    def compute_result(self, src, imm):
        return imm

class Instruction_LSR(OneRegAVRInstruction):
    opcode = '0110'
    name = 'lsr'

    def compute_result(self, src):
        return src >> 1

    def carry(self, src, res):
        return src[0]

    def negative(self, src, res):
        return 0

    def overflow(self, src, res):
        return self.negative(src, res) ^ self.carry(src, res)

class Instruction_MOV(NoFlags, TwoRegAVRInstruction):
    opcode = '001011'
    name = 'mov'

    def compute_result(self, src, dst):
        return src

class Instruction_MOVW(NoFlags, TwoDoubleRegAVRInstruction):
    opcode = '00000001'
    name = 'movw'

    def compute_result(self, src, dst):
        return src

class Instruction_MUL(TwoRegAVRInstruction):
    opcode = "100111"
    name = 'mul'

    def compute_result(self, src, dst):
        return src * dst

    def commit_result(self, res):
        # Stores to R1:R0
        self.put_reg_pair(res, "R1_R0")

    def carry(self, src, dst, res):
        return res[15]

class Instruction_MULS(TwoRegAVRInstruction):
    bin_format = '00000010ddddrrrr'
    name = 'muls'

    def fetch_operands(self):
        # Regs 16 - 31 only
        src = self.get_reg("1" + self.data['r'])
        dst = self.get_reg("1" + self.data['d'])
        return src, dst

    def compute_result(self, src, dst):
        src = src.widen_signed(DOUBLEREG_TYPE)
        dst = dst.widen_signed(DOUBLEREG_TYPE)
        src.is_signed = True
        dst.is_signed = True
        return src * dst

    def commit_result(self, res):
        # Stores to R1:R0
        self.put_reg_pair(res, 'R1_R0')

    def carry(self, src, dst, res):
        return res[15]

class Instruction_MULSU(TwoRegAVRInstruction):
    bin_format = '000000110ddd0rrr'
    name = 'mulsu'
    def fetch_operands(self):
        # Regs 16 - 23 only
        src = self.get_reg("10" + self.data['r'])
        dst = self.get_reg("10" + self.data['d'])
        return src, dst

    def compute_result(self, src, dst):
        src.is_signed = True
        dst.is_signed = False
        return src * dst

    def commit_result(self, res):
        # Stores to R1:R0
        self.put_reg_pair(res, 'R1_R0')

    def carry(self, src, dst, res):
        return res[15]

class Instruction_NEG(OneRegAVRInstruction):
    opcode = '0001'
    name = 'neg'

    def compute_result(self, src):
        return 0 - src

    # TODO Half-carry
    # TODO Overflow
    def negative(self, src, res):
        return res[7]

    def carry(self, src, res):
        return res != 0

class Instruction_NOP(NoFlags, AVRInstruction):
    bin_format = "0000000000000000"
    name = 'nop'
    def compute_result(self, *args):
        pass

class Instruction_OR(TwoRegAVRInstruction):
    opcode = "001010"
    name = 'or'

    def compute_result(self, src, dst):
        return src | dst

    def negative(self, src, dst, res):
        return res[7]

    def overflow(self, src, dst, res):
        return 0

class Instruction_ORI(RegImmAVRInstruction):
    opcode = '0110'
    name = 'ori'

    def compute_result(self, src, imm):
        return src | imm

    def negative(self, src, imm, res):
        return res[7]

    def overflow(self, src, imm, res):
        return 0

class Instruction_ROR(OneRegAVRInstruction):
    # Rotate right with carry-in
    opcode = '0111'
    name = 'ror'

    def compute_result(self, src):
        carry = self.get_flag(AVRFlagIndex.C_Carry)
        src >>= 1
        src[7] = carry
        return src

    def carry(self, src, res):
        return src[0]

    def negative(self, src, res):
        return res[7]

    def overflow(self, src, res):
        return self.negative(src, res) ^ self.carry(src, res)

class Instruction_SBC(TwoRegAVRInstruction):
    opcode = '000010'
    name = 'sbc'

    def compute_result(self, src, dst):
        return dst - src - self.get_carry()

    def half_carry(self, src, dst, res):
        return compute_carry_sub(3, src, dst, res)

    def carry(self, src, dst, res):
        return compute_carry_sub(7, src, dst, res)

    def overflow(self, src, dst, res):
        return compute_overflow_sub(src, dst, res)

    def negative(self, src, dst, res):
        return res[7]

class Instruction_SBCI(RegImmAVRInstruction):
    opcode = '0100'
    name = 'sbci'

    def compute_result(self, src, imm):
        return src - imm - self.get_carry()

    def overflow(self, src, imm, res):
        return compute_overflow_sub(imm, src, res)

    def carry(self, src, imm, res):
        return compute_carry_sub(7, imm, src, res)

    def half_carry(self, src, imm, res):
        return compute_carry_sub(3, imm, src, res)

    def negative(self, src, dst, res):
        return res[7]

class Instruction_SBIW(DoubleRegImmAVRInstruction):
    opcode = "10010111"
    name = 'sbiw'

    def compute_result(self, src, imm):
        return src - imm

    def overflow(self, src, imm, res):
        return compute_overflow_sub(imm, src, res)

    def carry(self, src, imm, res):
        return compute_carry_sub(7, imm, src, res)

    def half_carry(self, src, imm, res):
        return compute_carry_sub(3, imm, src, res)

    def negative(self, src, dst, res):
        return res[7]

class Instruction_SWAP(NoFlags, OneRegAVRInstruction):
    opcode = "0010"
    name = "swap"

    def compute_result(self, val):
        return (val >> 4) | (val << 4)

class Instruction_SUBI(RegImmAVRInstruction):
    opcode = "0101"
    name = "subi"

    def compute_result(self, dst, imm):
        return dst - imm

    def half_carry(self, dst, imm, res):
        return compute_carry_sub(3, imm, dst, res)

    def carry(self, dst, imm, res):
        return compute_carry_sub(3, imm, dst, res)

    def negative(self, dst, imm, res):
        return res[7]

    def overflow(self, dst, imm, res):
        return compute_overflow_sub(imm, dst, res)

class Instruction_SUB(TwoRegAVRInstruction):
    opcode = "000110"
    name = "sub"

    def compute_result(self, src, dst):
        return dst - src

    def half_carry(self, src, dst, res):
        return compute_carry_sub(3, src, dst, res)

    def carry(self, src, dst, res):
        return compute_carry_sub(7, src, dst, res)

    def negative(self, src, dst, res):
        return res[7]

    def overflow(self, src, dst, res):
        return compute_overflow_sub(src, dst, res)

class Instruction_XCH(NoFlags, AVRInstruction):
    bin_format = "1001001rrrrr0100"
    name = "xch"

    def fetch_operands(self):
        return (self.get_reg(self.data["r"]), )

    def compute_result(self, src):
        addr = self.get(self.arch.registers["Z"][0], DOUBLEREG_TYPE).cast_to(Type.int_24)
        segment = self.get(self.arch.registers["RAMPZ"][0], REG_TYPE).cast_to(Type.int_24) << 16
        dataval = self.load_data(segment + addr, Type.int_8)
        self.put_reg(dataval, self.data["r"])
        self.store_data(src, segment + addr)

class Instruction_CP(Instruction_SUB):
    opcode = "000101"
    name = 'cp'

    def commit_result(self, res):
        pass

class Instruction_CPC(Instruction_SBC):
    opcode = "000001"
    name = 'cpc'

    def commit_result(self, res):
        pass

class Instruction_CPI(Instruction_SUBI):
    opcode = '0011'
    name = 'cpi'

    def commit_result(self, res):
        pass


# DATA MEMORY ACCESS INSTRUCTIONS
#
# These instructions read or write data memory in some way, without altering control flow.

class Instruction_LAGeneric(NoFlags, AVRInstruction):
    def fetch_operands(self):
        z = self.get(self.arch.registers["Z"][0], DOUBLEREG_TYPE).cast_to(Type.int_32)
        rampz = self.get(self.arch.registers["RAMPZ"][0], REG_TYPE).cast_to(Type.int_32)
        self._target = (rampz << 16) + z #pylint:disable=attribute-defined-outside-init
        self._val = self.load_data(self._target, Type.int_8) #pylint:disable=attribute-defined-outside-init
        dst = self.get_reg(self.data["d"])
        return self._val, dst

    def commit_result(self, res):
        self.store_data(res, self._target)
        self.put_reg(self._val, self.data["d"])


class Instruction_LAC(Instruction_LAGeneric):
    bin_format = "1001001ddddd0110"
    name = 'lac'

    def compute_result(self, val, dst):
        return (0xff - dst) & val

class Instruction_LAS(Instruction_LAGeneric):
    bin_format = "1001001ddddd1010"
    name = 'las'

    def compute_result(self, val, dst):
        return val | dst

class Instruction_LAT(Instruction_LAGeneric):
    bin_format = "1001001ddddd0111"
    name = 'lat'

    def compute_result(self, val, dst):
        return val ^ dst

class LoadStoreInstruction(NoFlags, AVRInstruction):
    def process_address_operand(self):
        """This function computes the address for the load or store instruction,
        taking care of the correct segment register (RAMPX/Y/Z).
        It also applies any specified post-increment/pre-decrement.
        """

        # figure out which register (y or z) to operate on
        index_reg = self.arch.registers[self.data["index"]][0]
        segment_reg = self.arch.registers["RAMP" + self.data["index"]][0]

        # compute the address
        segment = self.get(segment_reg, REG_TYPE).cast_to(Type.int_24) << 16
        addr =  self.get(index_reg, DOUBLEREG_TYPE).cast_to(Type.int_24)

        # special mode: pre-decrement
        if self.data["s"] and self.data["q"] == 2:
            addr -= 1
            self.put((addr >> 16).cast_to(Type.int_8), segment_reg)
            self.put(addr.cast_to(Type.int_16), index_reg)

        # special mode: post-increment
        if self.data["s"] and self.data["q"] == 1:
            new_addr = addr + 1
            self.put((new_addr >> 16).cast_to(Type.int_8), segment_reg)
            self.put(new_addr.cast_to(Type.int_16), index_reg)

        # optional offset if not special mode
        offset = self.data["q"] if not self.data["s"] else 0
        return addr + offset + segment


class Instruction_LDGeneric(LoadStoreInstruction):
    name = "ld"
    def fetch_operands(self):
        return (self.process_address_operand(), )

    def compute_result(self, addr):
        return self.load_data(addr, REG_TYPE)

    def commit_result(self, res):
        self.put_reg(res, self.data["d"])


class Instruction_LDx(Instruction_LDGeneric):
    bin_format = '1001000ddddd11qq'

    def match_instruction(self, data, bitstrm):
        data["q"] = int(data["q"], 2)
        data["s"] = 1 if data["q"] in [1, 2] else 0
        data["index"] = "X"
        if data["q"] not in [0, 1, 2]:
            raise ParseError()

class Instruction_LDyz(Instruction_LDGeneric):
    bin_format = '10qsqq0dddddyqqq'

    def match_instruction(self, data, bitstrm):
        data["s"] = int(data["s"], 2)
        data["q"] = int(data["q"], 2)
        data["index"] = "Y" if int(data["y"], 2) == 1 else "Z"

        # if "special" form, not all patterns are valid LD instructions.
        # only q=1/2 are valid for special form
        if data["s"] == 1 and data["q"] not in [1,2]:
            raise ParseError()

class Instruction_STGeneric(LoadStoreInstruction):
    name = "st"

    def fetch_operands(self):
        return (self.process_address_operand(), self.get_reg(self.data["r"]))

    def compute_result(self, addr, val):
        self.store_data(val, addr)

class Instruction_STx(Instruction_STGeneric):
    bin_format = '1001001rrrrr11qq'

    def match_instruction(self, data, bitstrm):
        data["q"] = int(data["q"], 2)
        data["s"] = 1 if data["q"] in [1, 2] else 0
        data["index"] = "X"
        if data["q"] not in [0, 1, 2]:
            raise ParseError()

class Instruction_STyz(Instruction_STGeneric):
    bin_format = "10qsqq1rrrrryqqq"

    def match_instruction(self, data, bitstrm):
        data["s"] = int(data["s"], 2)
        data["q"] = int(data["q"], 2)
        data["index"] = "Y" if int(data["y"], 2) == 1 else "Z"

        # if "special" form, not all patterns are valid ST instructions.
        # only q=1/2 are valid for special form
        if data["s"] == 1 and data["q"] not in [1,2]:
            raise ParseError()

class Instruction_LDS(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd0000"
    name = 'lds'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] = read_trailer(bitstrm)
        self.bitwidth = 32
        return data

    def fetch_operands(self):
        dst = self.get_reg(self.data['d'])
        imm = int(self.data['k'], 2)
        return dst, imm

    def compute_result(self, dst, imm):
        segment = self.get_reg("RAMPD").cast_to(Type.int_32) << 16
        return self.load_data(segment + imm, REG_TYPE)

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

# TODO: LDS16
# note that the LDS16 encoding overlaps with the LD z+q instruction, need to select correct
# decoding based on what instruction the CPU supports

class Instruction_POP(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd1111"
    name = 'pop'

    def fetch_operands(self):
        return (None, )

    def compute_result(self, none):
        sp = self.get_reg('SP')
        self.put_reg(sp + 1, 'SP')
        return self.load_data(sp, REG_TYPE)

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class Instruction_PUSH(NoFlags, AVRInstruction):
    bin_format = "1001001ddddd1111"
    name = 'push'

    def fetch_operands(self):
        return (self.get_reg(self.data['d']), )


    def compute_result(self, src):
        sp = self.get_reg('SP')
        sp -= 1
        self.store_data(src, sp)
        self.put_reg(sp, 'SP')

class Instruction_STS(NoFlags, AVRInstruction):
    bin_format = "1001001rrrrr0000"
    name = "sts"

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        data["k"] = read_trailer(bitstrm)
        self.bitwidth = 32
        return data

    def fetch_operands(self):
        return (self.get_reg(self.data["r"]), int(self.data["k"], 2))

    def compute_result(self, val, imm):
        segment = self.get_reg("RAMPD").cast_to(Type.int_32) << 16
        self.store_data(val, segment + imm)



# PROGRAM MEMORY ACCESS INSTRUCTIONS
#
# These instructions read or write program memory in some way, without altering control flow.

class Instruction_ELPM(NoFlags, AVRInstruction):
    bin_format = "1001010110011000"
    name = 'elpm'

    def fetch_operands(self):
        z = self.get_reg('Z').cast_to(Type.int_24)
        rampz = self.get_reg('RAMPZ')
        src = rampz.cast_to(Type.int_24) << 16
        src += z
        return (src, )

    def compute_result(self, src):
        return self.load_program(src, REG_TYPE)

    def commit_result(self, ret):
        self.put_reg(ret, 'R0')

class Instruction_ELPMd(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd0110"
    name = 'elpm'

    def fetch_operands(self):
        z = self.get_reg('Z').cast_to(Type.int_24)
        rampz = self.get_reg('RAMPZ')
        src = rampz.cast_to(Type.int_24) << 16
        src += z
        return (src, )

    def compute_result(self, src):
        return self.load_program(src, REG_TYPE)

    def commit_result(self, ret):
        self.put_reg(ret, self.data['d'])

class Instruction_ELPMplus(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd0111"
    name = 'elpm'

    def fetch_operands(self):
        z = self.get_reg('Z').widen_unsigned(Type.int_24)
        rampz = self.get_reg('RAMPZ')
        src = rampz.cast_to(Type.int_24) << 16
        src += z
        # Post-increment Z
        z += 1
        self.put_reg(z, 'Z')
        return (src, )

    def compute_result(self, src):
        return self.load_program(src, REG_TYPE)

    def commit_result(self, ret):
        self.put_reg(ret, self.data['d'])

class Instruction_LPM(NoFlags, AVRInstruction):
    bin_format = "1001010111001000"
    name = 'lpm'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (z, )

    def compute_result(self, src):
        return self.load_program(src, REG_TYPE)

    def commit_result(self, ret):
        self.put_reg(ret, 'R0')

class Instruction_LPMd(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd0100"
    name = 'lpm'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (z, )

    def compute_result(self, src):
        return self.load_program(src, REG_TYPE)

    def commit_result(self, ret):
        self.put_reg(ret, self.data['d'])

class Instruction_LPMplus(Instruction_LPMd):
    bin_format = "1001000ddddd0101"
    name = 'lpm+'

    def fetch_operands(self):
        # Post-increment z
        z = self.get_reg('Z')
        self.put_reg(z + 1, 'Z')
        return (z, )



# CONTROL FLOW INSTRUCTIONS
#
# These instructions change the control flow (jumps, branches, returns, ...).

class Instruction_BRBC(NoFlags, AVRInstruction):
    bin_format = '111101kkkkkkksss'
    name = 'brbc'

    def fetch_operands(self):
        # K is two's complement signed
        offset = bits_to_signed_int(self.data['k'])
        idx = int(self.data['s'], 2)
        return offset, idx

    def compute_result(self, offset, idx):
        sr = self.get_reg("SREG")
        self.relative_jump(sr[idx] == 0, offset + 1)

class Instruction_BRBS(NoFlags, AVRInstruction):
    bin_format = '111100kkkkkkksss'
    name = 'brbs'
    def fetch_operands(self):
        # K is two's complement signed
        offset = bits_to_signed_int(self.data['k'])
        idx = int(self.data['s'], 2)
        return offset, idx

    def compute_result(self, offset, idx):
        sr = self.get_reg("SREG")
        self.relative_jump(sr[idx] != 0, offset + 1)

class Instruction_CALL(NoFlags, AVRInstruction):
    bin_format = "1001010kkkkk111k"
    name = 'call'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] += read_trailer(bitstrm)
        self.bitwidth = 32
        return data

    def fetch_operands(self):
        # Unsigned
        return (int(self.data['k'], 2), )

    def compute_result(self, dst):
        sp = self.get_reg("SP")
        sp -= self.arch.call_sp_fix
        self.store_data(self.constant(self.get_pc() + 2, self.pc_type), sp)
        self.put_reg(sp, "SP")
        self.absolute_jump(None, dst, jumpkind=JumpKind.Call)

class Instruction_EICALL(NoFlags, AVRInstruction):
    bin_format = "1001010100011001"
    name = 'eicall'

    def fetch_operands(self):
        z = self.get_reg('Z').cast_to(Type.int_23)
        eind = self.get_reg('EIND').cast_to(Type.int_6)
        dst = eind.cast_to(Type.int_23) << 16
        dst += z
        return (dst, )

    def compute_result(self, dst):
        self.absolute_jump(None, dst, jumpkind=JumpKind.Call)

class Instruction_EIJMP(NoFlags, AVRInstruction):
    bin_format = "1001010000011001"
    name = 'eijmp'

    def fetch_operands(self):
        z = self.get_reg('Z').cast_to(Type.int_23)
        eind = self.get_reg('EIND').cast_to(Type.int_6)
        dst = eind.cast_to(Type.int_23) << 16
        dst += z
        return (dst << 1,)

    def compute_result(self, dst):
        self.jump(None, dst)

class Instruction_ICALL(NoFlags, AVRInstruction):
    # Call address at Z.  Post decrement SP
    bin_format = '1001010100001001'
    name = 'icall'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (z, )

    def compute_result(self, dst):
        sp = self.get_reg('SP') - self.arch.call_sp_fix
        self.store_data(self.constant(self.get_pc() + 1, self.pc_type), sp)
        self.put_reg(sp, 'SP')
        self.absolute_jump(None, dst, jumpkind=JumpKind.Call)

class Instruction_IJMP(NoFlags, AVRInstruction):
    bin_format = '1001010000001001'
    name = 'ijmp'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (z, )

    def compute_result(self, dst):
        self.absolute_jump(None, dst)

class Instruction_JMP(NoFlags, AVRInstruction):
    bin_format = "1001010kkkkk110k"
    name = 'jmp'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] += read_trailer(bitstrm)
        self.bitwidth = 32
        return data

    def fetch_operands(self):
        # Unsigned
        return (int(self.data['k'], 2), )

    def compute_result(self, dst):
        self.absolute_jump(None, dst)

class Instruction_RCALL(NoFlags, AVRInstruction):
    # A relative call to k
    bin_format = "1101kkkkkkkkkkkk"
    name = 'rcall'

    def fetch_operands(self):
        return (bits_to_signed_int(self.data['k']), )

    def compute_result(self, dst):
        # Store return address
        sp = self.get_reg('SP')
        sp -= self.arch.call_sp_fix
        self.store_data(self.constant(self.get_pc() + 1, self.pc_type), sp)
        self.put_reg(sp, "SP")
        # HACK: if the call target is the next instruction, treat this as a boring jump
        # gcc likes to use rcall to reserve space on stack. these calls are not actually calls,
        # they are just there to decrease the stack pointer by 2/3 (depending on arch) bytes
        jumpkind = JumpKind.Call if dst != 0 else JumpKind.Boring
        self.relative_jump(None, dst + 1, jumpkind=jumpkind)

class Instruction_RET(NoFlags, AVRInstruction):
    bin_format = "1001010100001000"
    name = 'ret'

    def compute_result(self, *args):
        sp = self.get_reg("SP")
        self.put_reg(sp + self.arch.call_sp_fix, 'SP')
        dst = self.load_data(sp, int_type_for_size(self.arch.call_sp_fix * 8))
        self.absolute_jump(None, dst, jumpkind=JumpKind.Ret)

class Instruction_RETI(NoFlags, AVRInstruction):
    bin_format = "1001010100011000"
    name = 'ret'

    def compute_result(self, *args):
        # Pre-increment SP
        sp = self.get_reg("SP")
        self.put_reg(sp + self.arch.call_sp_fix, 'SP')
        dst = self.load_data(sp, int_type_for_size(self.arch.call_sp_fix * 8))
        self.set_flag(AVRFlagIndex.I_Interrupt, 1)
        self.absolute_jump(None, dst, jumpkind=JumpKind.Ret)

class Instruction_RJMP(NoFlags, AVRInstruction):
    # A relative call to k
    bin_format = "1100kkkkkkkkkkkk"
    name = 'rjmp'

    def fetch_operands(self):
        return (bits_to_signed_int(self.data['k']),)

    def compute_result(self, dst):
        self.relative_jump(None, dst + 1)

class SkipInstruction(NoFlags, AVRInstruction):
    def apply_context(self, past, future):
        self.next_size = future[0].bytewidth #pylint:disable=attribute-defined-outside-init

    def fetch_operands(self):
        return (self.get_reg(self.data["r"]), int(self.data["b"], 2))

    def commit_result(self, skip):
        self.jump(skip, self.addr + self.next_size + 2)

class Instruction_SBRC(SkipInstruction):
    bin_format = "1111110rrrrr0bbb"
    name = "sbrc"
    def compute_result(self, reg, bit):
        return ~reg[bit]

class Instruction_SBRS(SkipInstruction):
    bin_format = "1111111rrrrr0bbb"
    name = "sbrs"
    def compute_result(self, reg, bit):
        return reg[bit]

class Instruction_CPSE(SkipInstruction):
    bin_format = '000100rdddddrrrr'
    name = "cpse"

    def fetch_operands(self):
        return (self.get_reg(self.data["r"]), self.get_reg(self.data["d"]))

    def compute_result(self, src, dst):
        return src == dst



# SIDE-EFFECT INSTRUCTIONS
#
# These instructions do things with environmental side effects, such as changing IO registers
# or physical processor properties (sleep mode, watchdog, etc).

class Instruction_CBI(NoFlags, AVRInstruction):
    bin_format = '10011000AAAAAbbb'
    name = 'cbi'

    def fetch_operands(self):
        # Bottom 32 io regs
        ior = self.get_ioreg("0" + self.data['A'])
        idx = int(self.data['b'], 2)
        return ior, idx

    def compute_result(self, ior, idx):
        ior[idx] = 0
        return ior

    def commit_result(self, res):
        self.put_ioreg(res, "0" + self.data['A'])

class Instruction_IN(NoFlags, AVRInstruction):
    bin_format = '10110AAdddddAAAA'
    name = "in"

    def fetch_operands(self):
        return (self.get_ioreg(self.data['A']), )

    def compute_result(self, src):
        return src

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class Instruction_OUT(NoFlags, AVRInstruction):
    bin_format = '10111AArrrrrAAAA'
    name = "out"
    def fetch_operands(self):
        return  (self.get_reg(self.data['r']), )

    def compute_result(self, res):
        return res

    def commit_result(self, res):
        self.put_ioreg(res, self.data['A'])

class Instruction_WDR(NoFlags, AVRInstruction):
    bin_format = "1001010110101000"
    name = 'wdr'

    def compute_result(self, *args):
        return None
        # EDG says: Uh... no.
class Instruction_SLEEP(AVRInstruction):
    bin_format = "1001010110001000"
    name = "sleep"



class LifterAVR(GymratLifter):

    instrs = {
        Instruction_ADC,
        Instruction_ADD,
        Instruction_ADIW,
        Instruction_AND,
        Instruction_ANDI,
        Instruction_ASR,
        Instruction_BCLR,
        Instruction_BLD,
        Instruction_BRBC,
        Instruction_BRBS,
        # NOTE: The following instructions will lift to BRBC and BRBS
        #BRCC
        #BRCS
        #BREQ
        #BRGE
        #BRHC
        #BRHS
        #BRID
        #BRIE
        #BRLO
        #BRLT
        #BRMI
        #BRNE
        #BRPL
        #BRSH
        #BRTC
        #BRVC
        #BRVS
        # TODO: BREAK
        Instruction_BSET,
        Instruction_BST,
        Instruction_CALL,
        Instruction_CBI,
        # CBR Virtual; see ANDI
        # Note: The following instructions will lift to BCLR
        #CLC
        #CLH
        #CLI
        #CLN
        #CLS
        #CLT
        #CLV
        #CLZ
        # CLR Virtual; see EOR
        Instruction_COM,
        Instruction_CP,
        Instruction_CPC,
        Instruction_CPI,
        Instruction_DEC,
        # TODO: DES
        Instruction_EICALL,
        Instruction_EIJMP,
        Instruction_ICALL,
        Instruction_IJMP,
        Instruction_ELPM,
        Instruction_ELPMd,
        Instruction_ELPMplus,
        Instruction_EOR,
        # TODO: FMUL
        # TODO: FMULS
        # TODO: FMULSU
        Instruction_IN,
        Instruction_INC,
        Instruction_JMP,
        Instruction_LAC,
        Instruction_LAS,
        Instruction_LAT,
        Instruction_LDx,
        Instruction_LDyz,
        Instruction_LDI,
        Instruction_LDS,
        Instruction_LPM,
        Instruction_LPMd,
        Instruction_LPMplus,
        Instruction_LSR,
        Instruction_MOV,
        Instruction_MOVW,
        Instruction_MUL,
        Instruction_MULS,
        Instruction_MULSU,
        Instruction_NEG,
        Instruction_NOP,
        Instruction_OR,
        Instruction_ORI,
        Instruction_OUT,
        Instruction_POP,
        Instruction_PUSH,
        Instruction_RCALL,
        Instruction_RET,
        Instruction_RETI,
        Instruction_RJMP,
        #ROL Virtual;
        Instruction_ROR,
        Instruction_SBC,
        Instruction_SBCI,
        # TODO: SBI
        # TODO: SBIC
        # TODO: SBIS
        Instruction_SBIW,
        #SBR Virtual; See OR
        Instruction_SBRC,
        Instruction_SBRS,
        Instruction_CPSE,
        # Note: The following instructions will lift to BSET
        #SEC
        #SEH
        #SEI
        #SEN
        #SES
        #SET
        #SEV
        #SEZ
        Instruction_SLEEP,
        # TODO: SPM
        # TODO: SPM2
        Instruction_STx,
        Instruction_STyz,
        Instruction_STS,
        Instruction_SUB,
        Instruction_SUBI,
        Instruction_SWAP,
        # TST Virtual; see AND
        Instruction_WDR,
        Instruction_XCH,
        }


register(LifterAVR, "AVR")


def main():
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    tests = [
        b'\x00\x00',  # NOP
        b'\x23\x01',  # MOVW
        b'\x46\x02',  # MULS
    ]
    print("Decoder test:")
    for num, test in enumerate(tests):
        print(num)
        lifter = LifterAVR(ArchAVR(), 0)
        lifter.lift(data=test)

    print("Lifter test:")
    for test in tests:
        lifter = LifterAVR(ArchAVR(), 0)
        lifter.lift(data=test)
        lifter.irsb.pp()

    print("Full tests:")
    fulltest = b"".join(tests)
    lifter = LifterAVR(ArchAVR(), 0)
    lifter.lift(data=fulltest)
    lifter.irsb.pp()


if __name__ == "__main__":
    main()
