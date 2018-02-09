import struct
from arch_avr import ArchAVR
from pyvex.lift.util import *
from pyvex.lift import register
from pyvex.expr import int_type_for_size
import bitstring
import sys
import os
import re
import pyvex
import archinfo
from arch_avr import ArchAVR

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
    def get_reg(self, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 5:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible registers.  See get_reg_16_31")
            else:
                return self.get(int(name, 2), REG_TYPE)
        else:
            try:
                reg, width = self.arch.registers[name]
                ty = REG_TYPE if width == 1 else DOUBLEREG_TYPE
                return self.get(reg, ty)
            except KeyError:
                raise ValueError("Invalid register for name: " + name)

    def put_reg(self, value, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 5:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible registers.  See get_reg_16_31")
            else:
                self.put(value, int(name, 2))
                return
        else:
            try:
                reg, _ = self.arch.registers[name]
                self.put(value, reg)
                return
            except KeyError:
                raise ValueError("Invalid register for put: " + name)

    def get_reg_pair(self, name_num):
        if isinstance(name_num, str) and re.match('^[01]+$', name_num):
            if len(name_num) != 4:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible double registers.")
            else:
                num = int(name_num, 2)
        else:
            num = name_num
        try:
            offset = self.arch.registers['R%d_R%d' % (2 * num + 1, 2 * num)][0]
            return self.get(offset, DOUBLEREG_TYPE)
        except KeyError:
            raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num))

    def put_reg_pair(self, value, name_num):
        if isinstance(name_num, str) and re.match('^[01]+$', name_num):
            if len(name_num) != 4:
                # The ISA has special restrictions on what instructions use which
                # regs.  5-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible double registers.")
            else:
                num = int(name_num, 2)
        elif isinstance(name_num, int):
            num = name_num

            try:
                offset = self.arch.registers['R%d_R%d' % (2 * num + 1, 2 * num)]
                return self.put(value, offset)
            except KeyError:
                raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num))
        else:
            try:
                offset = self.arch.registers[name_num][0]
                return self.put(value, offset)
            except KeyError:
                raise ValueError("Invalid reg pair: " + 'R%d_R%d' % (2 * num + 1, 2 * num))


    def get_ioreg(self, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 6:
                # The ISA has special restrictions on what instructions use which
                # regs.  6-bit IO regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible IO registers.")
            else:
                return self.get(self.arch.ioreg_offset + int(name, 2), REG_TYPE)
        else:
            try:
                reg, width = self.arch.registers[name]
                ty = REG_TYPE if width == 1 else DOUBLEREG_TYPE
                return self.get(reg, ty)
            except KeyError:
                raise ValueError("Invalid register for name: " + name)

    def put_ioreg(self, value, name):
        if isinstance(name, str) and re.match('^[01]+$', name):
            if len(name) != 6:
                # The ISA has special restrictions on what instructions use which
                # regs.  6-bit regs are any reg.  Otherwise you must specify
                raise ValueError("Must correctly constrain possible IO registers. ")
            else:
                self.put(value, self.arch.ioreg_offset + int(name, 2))
                return
        else:
            try:
                reg, _ = self.arch.registers[name]
                self.put(value, reg)
                return
            except KeyError:
                raise ValueError("Invalid register for put: " + name)

    # Memory access stuff is weird

    def load_program(self, addr, ty):
        # Let's assume the program memory is in the bottom bits of the address sapce.
        # Just load it
        return self.load(addr, ty)

    def load_data(self, addr, ty):
        # Assume the data is in the upper half of the address space.
        return self.load(addr.cast_to(Type.int_32) + self.arch.data_offset, ty)

    def store_program(self, val, addr):
        self.store(val, addr)

    def store_data(self, val, addr):
        self.store(val, addr.cast_to(Type.int_32) + self.arch.data_offset)

    #################################
    #      Flag access helpers      #
    #################################

    def get_flag(self, idx):
        assert idx >= 0 and idx < 8
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

    def interrupt_enable(self, *args):
        return None

    def transfer(self, *args):
        return None

    def half_carry(self, *args):
        return None

    def signed(self, *args):
        v = self.overflow(*args)
        n = self.negative(*args)
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
        else:
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
            if data['o'] != self.opcode:
                raise ParseError("Mismatched opcode, expected %s, got %s" % (self.opcode, data['o']))
        else:
            if 'o' in data:
                raise Exception("Instruction " + self.name + " should probably have an opcode")
    def compute_flags(self, *args):
        i = self.interrupt_enable(*args)
        t = self.transfer(*args)
        h = self.half_carry(*args)
        s = self.signed(*args)
        v = self.overflow(*args)
        z = self.zero(*args)
        c = self.carry(*args)
        self.set_flags(i, t, h, s, v, z, c)


    # PC helpers
    #
    # Note that the program counter in AVR is always 2-byte aligned.
    # So the instruction's least significant bit of the bytewise address is always 0,
    # which is why the instruction pointer must be interpreted as a 16-bitwise address.
    #
    # So if PC = 0x8, that refers to the instruction located at byte offset 0x8<<1 = 0x10

    def relative_jump(self, condition, offset, **kwargs):
        self.jump(condition, self.addr + (offset << 1), **kwargs)

    def absolute_jump(self, condition, addr, **kwargs):
        self.jump(condition, addr << 1, **kwargs)

    def get_pc(self):
        return self.get("pc", Type.int_24)
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

#class Instruction_BREAK(NoFlags, AVRInstruction):

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


class Instruction_CALL(NoFlags, AVRInstruction):
    bin_format = "1001010kkkkk111k"
    name = 'call'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] += read_trailer(bitstrm)
        self.bitsize = 32
        return data

    def fetch_operands(self):
        # Unsigned
        return (int(self.data['k'], 2), )

    def compute_result(self, dst):
        sp = self.get_reg("SP")
        sp -= self.arch.call_sp_fix
        self.store_data(self.get_pc() + 2, sp + 1)
        self.put_reg(sp, "SP")
        self.absolute_jump(None, dst, jumpkind=JumpKind.Call)

class Instruction_CBI(NoFlags, AVRInstruction):
    bin_format = '10011000AAAAAbbb'
    name = 'cbi'

    def fetch_operands(self):
        # Bottom 32 io regs
        ior = self.get_ioreg("0" + self.data['A'])
        idx = int(self.data['b'], 2)
        return ior, idx

    def compute_result(self, ior):
        ior[idx] = 0
        return ior

    def commit_result(self, res):
        self.put_ioreg(res, "0" + self.data['A'])

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

# TODO: DES

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


class Instruction_EOR(TwoRegAVRInstruction):
    opcode = '001001'
    name = 'eor'

    def compute_result(self, src, dst):
        return src ^ dst

    def overflow(self, *args):
        return 0

    def negative(self, src, dst, res):
        return res[7]


# TODO FMUL

# TODO FMULS

# TODO FMULSU

class Instruction_ICALL(NoFlags, AVRInstruction):
    # Call address at Z.  Post decrement SP
    bin_format = '1001010100001001'
    name = 'icall'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (z, )

    def compute_result(self, dst):
        sp = self.get_reg('SP') - self.arch.call_sp_fix
        self.store_data(self.get_pc(), sp + 1)
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

class Instruction_IN(NoFlags, AVRInstruction):
    bin_format = '10110AAdddddAAAA'
    name = "in"

    def fetch_operands(self):
        return (self.get_ioreg(self.data['A']), )

    def compute_result(self, src):
        return src

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])


class Instruction_INC(NoFlags, OneRegAVRInstruction):
    opcode = '1011'
    name = 'inc'

    def compute_result(self, src):
        return src + 1

class Instruction_JMP(NoFlags, AVRInstruction):
    bin_format = "1001010kkkkk110k"
    name = 'jmp'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] += read_trailer(bitstrm)
        self.bitsize = 32
        return data

    def fetch_operands(self):
        # Unsigned
        return (int(self.data['k'], 2), )

    def compute_result(self, dst):
        self.absolute_jump(None, dst)

class Instruction_LAC(NoFlags, AVRInstruction):
    bin_format = "1001001rrrrr1111"
    name = 'lac'

    def fetch_operands(self):
        z = self.get_reg('Z')
        val = self.load_data(z, REG_TYPE)
        dst = self.get_reg(self.data['r'])
        return val, dst

    def compute_result(self, val, dst):
        return (0xff - dst) & val

    def commit_result(self, res):
        self.put_reg(res, self.data['r'])

class Instruction_LAS(Instruction_LAC):
    bin_format = "1001001rrrrr1010"
    name = 'las'

    def compute_result(self, val, dst):
        return val | dst

class Instruction_LAT(Instruction_LAC):
    bin_format = "1001001rrrrr0111"
    name = 'lat'

    def compute_result(self, val, dst):
        return val ^ dst

class Instruction_LDDX(NoFlags, AVRInstruction):
    bin_format = '1001000ddddd1100'
    name = 'lddX'

    def fetch_operands(self):
        x = self.get_reg('X')
        return (self.load_data(x, REG_TYPE), )

    def compute_result(self, val):
        return val

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class Instruction_LDDXplus(Instruction_LDDX):
    bin_format = '1001000ddddd1101'
    name = 'lddX+'

    def fetch_operands(self):
        x = self.get_reg('X')
        val = (self.load_data(x, REG_TYPE),)
        self.put_reg(x + 1, 'X')
        return val

class Instruction_LDDXminus(Instruction_LDDX):
    bin_format = '1001000ddddd1110'
    name = 'ldd-X'


    def fetch_operands(self):
        x = self.get_reg('X') - 1
        self.put_reg(x, 'X')
        val = (self.load_data(x, REG_TYPE),)
        return val

class Instruction_LDDY(NoFlags, AVRInstruction):
    # TODO: Looks like a mistake in the ISA here.  Is it 1000 or 1001?
    bin_format = '1001000ddddd1000'
    name = 'lddY'

    def fetch_operands(self):
        y = self.get_reg('Y')
        return (self.load_data(y, REG_TYPE), )

    def compute_result(self, val):
        return val

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class Instruction_LDDYplus(Instruction_LDDY):
    bin_format = '1001000ddddd1001'
    name = 'lddY+'

    def fetch_operands(self):
        y = self.get_reg('Y')
        val = (self.load_data(y, REG_TYPE),)
        self.put_reg(y + 1, 'Y')
        return val

class Instruction_LDDYminus(Instruction_LDDY):
    bin_format = '1001000ddddd1010'
    name = 'ldd-Y'

    def fetch_operands(self):
        y = self.get_reg('Y') - 1
        self.put_reg(x, 'Y')
        val = (self.load_data(y, REG_TYPE),)
        return val

class Instruction_LDDYq(Instruction_LDDY):
    bin_format = '10q0qq0ddddd1qqq'

    def fetch_operands(self):
        q = int(self.data['q'], 2)
        y = self.get_reg('Y') + q
        val = (self.load_data(y, REG_TYPE),)
        return val

class Instruction_LDDZ(NoFlags, AVRInstruction):
    bin_format = '1001000ddddd0000'
    name = 'lddZ'

    def fetch_operands(self):
        z = self.get_reg('Z')
        return (self.load_data(z, REG_TYPE), )

    def compute_result(self, val):
        return val

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])

class Instruction_LDDZplus(Instruction_LDDZ):
    bin_format = '1001000ddddd0001'
    name = 'lddZ+'

    def fetch_operands(self):
        z = self.get_reg('Z')
        val = (self.load_data(z, REG_TYPE),)
        self.put_reg(z + 1, 'Z')
        return val

class Instruction_LDDZminus(Instruction_LDDZ):
    bin_format = '1001000ddddd0010'
    name = 'ldd-Z'

    def fetch_operands(self):
        z = self.get_reg('Z') - 1
        self.put_reg(x, 'Z')
        val = (self.load_data(z, REG_TYPE),)
        return val

class Instruction_LDDZq(Instruction_LDDZ):
    bin_format = '10q0qq0ddddd0qqq'

    def fetch_operands(self):
        q = int(self.data['q'], 2)
        z = self.get_reg('Y') + q
        val = (self.load_data(z, REG_TYPE),)
        return val


class Instruction_LDI(NoFlags, RegImmAVRInstruction):
    opcode = '1110'
    name = 'ldi'

    def compute_result(self, src, imm):
        return imm


class Instruction_LDS(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd0000"
    name = 'lds'

    def parse(self, bitstrm):
        data = AVRInstruction.parse(self, bitstrm)
        # get the rest of the imm
        data['k'] = read_trailer(bitstrm)
        self.bitsize = 32
        return data

    def fetch_operands(self):
        dst = self.get_reg(self.data['d'])
        imm = int(self.data['k'], 2)
        return dst, imm

    def compute_result(self, dst, imm):
        # TODO: Something about RAMPD
        return self.load_data(self.constant(imm, Type.int_32), REG_TYPE)

    def commit_result(self, res):
        self.put_reg(res, self.data['d'])


# TODO: LDS16
# note that the LDS16 encoding overlaps with the LD z+q instruction, need to select correct
# decoding based on what instruction the CPU supports

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


class Instruction_LSR(OneRegAVRInstruction):
    opcode = '0110'
    name = 'lsr'

    def compute_result(self, src):
        return src >> 1

    def carry(self, src, res):
        return src[0]

    def negative(self, *args):
        return 0

    def overflow(self, *args):
        return self.negative(*args) ^ self.carry(*args)


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


class Instruction_OUT(NoFlags, AVRInstruction):
    bin_format = '10111AArrrrrAAAA'
    name = "out"
    def fetch_operands(self):
        return  (self.get_reg(self.data['r']), )

    def compute_result(self, res):
        return res

    def commit_result(self, res):
        self.put_ioreg(res, self.data['A'])


class Instruction_POP(NoFlags, AVRInstruction):
    bin_format = "1001000ddddd1111"
    name = 'pop'

    def fetch_operands(self):
        return (None, )

    def compute_result(self, none):
        # Pre-increment SP
        sp = self.get_reg('SP')
        sp += 1
        self.put_reg(sp, 'SP')
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
        self.store_data(src, sp)
        sp -= 1
        self.put_reg(sp, 'SP')


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
        self.store_data(self.get_pc() + 1, sp + 1)
        self.put_reg(sp, "SP")
        self.relative_jump(None, dst + 1, jumpkind=JumpKind.Call)


class Instruction_RET(NoFlags, AVRInstruction):
    bin_format = "1001010100001000"
    name = 'ret'

    def compute_result(self, *args):
        sp = self.get_reg("SP")
        self.put_reg(sp + self.arch.call_sp_fix, 'SP')
        dst = self.load_data(sp + 1, int_type_for_size(self.arch.call_sp_fix * 8))
        self.absolute_jump(None, dst, jumpkind=JumpKind.Ret)


class Instruction_RETI(NoFlags, AVRInstruction):
    bin_format = "1001010100011000"
    name = 'ret'

    def compute_result(self, *args):
        # Pre-increment SP
        sp = self.get_reg("SP")
        self.put_reg(sp + self.arch.call_sp_fix, 'SP')
        dst = self.load_data(sp + 1, int_type_for_size(self.arch.call_sp_fix * 8))
        # Set GIE
        self.set_flag(MSPFlagIndex.GIE, 1)
        self.absolute_jump(None, dst, jumpkind=JumpKind.Ret)


class Instruction_RJMP(NoFlags, AVRInstruction):
    # A relative call to k
    bin_format = "1100kkkkkkkkkkkk"
    name = 'rjmp'

    def fetch_operands(self):
        return (bits_to_signed_int(self.data['k']),)

    def compute_result(self, dst):
        self.relative_jump(None, dst + 1)

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

    def overflow(self, *args):
        return self.negative(*args) ^ self.carry(*args)


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


# TODO: SBI
# TODO: SBIC
# TODO: SBIS

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

# TODO: SBRC
# TODO: SBRS

class Instruction_SLEEP(AVRInstruction):
    bin_format = "1001010110001000"
    name = "sleep"

class Instruction_ST(AVRInstruction):
    bin_format = '1001001rrrrr1100'
    name = 'st'
    def fetch_operands(self):
        return (self.get_reg(self.data['r']), )

    def compute_result(self, val):
        addr = self.get(self.arch.registers['X'][0], DOUBLEREG_TYPE)
        self.store_data(val, addr)

class Instruction_STplus(NoFlags, AVRInstruction):
    bin_format = '1001001rrrrr1101'
    name = 'st+'

    def fetch_operands(self):
        return (self.get_reg(self.data['r']), )

    def compute_result(self, val):
        # Post-increment
        addr = self.get(self.arch.registers['X'][0], DOUBLEREG_TYPE)
        self.store_data(val, addr)
        addr += 1
        self.put(addr, self.arch.registers['X'][0])

class Instruction_STminus(NoFlags,AVRInstruction):
    bin_format = '1001001rrrrr1110'
    name = 'st-'

    def fetch_operands(self):
        return (self.get_reg(self.data['r']),)

    def compute_result(self, val):
        # Pre-decrement
        addr = self.get(self.arch.registers['X'][0], DOUBLEREG_TYPE)
        addr -= 1
        self.store_data(val, addr)
        self.put(addr, self.arch.registers['X'][0])

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
    opcode = "00110"
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


class Instruction_WDR(NoFlags, AVRInstruction):
    bin_format = "1001010110101000"
    name = 'wdr'

    def compute_result(self, *args):
        return None
        # EDG says: Uh... no.

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

    def compute_result(self, src, imm):
        return src - imm


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
        #BREAK
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
        Instruction_BSET,
        Instruction_BST,
        Instruction_CALL,
        Instruction_CBI,
        #CBR Virtual; see ANDI
        #CLC Virtual; see BCLR
        #CLH
        #CLI
        #CLN
        #CLR Virtual; see EOR
        #CLS
        #CLT
        #CLV
        #CLZ
        Instruction_COM,
        Instruction_CP,
        Instruction_CPC,
        Instruction_CPI,
        #TODO: Instruction_CPSE,
        Instruction_DEC,
        # TODO: DES
        Instruction_EICALL,
        Instruction_EIJMP,
        Instruction_ELPM,
        Instruction_ELPMd,
        Instruction_ELPMplus,
        Instruction_EOR,
        # TODO: FMUL
        # TODO: FMULS
        # TODO: FMULSU
        # TODO: ICALL
        # TODO: IJMP
        Instruction_IN,
        Instruction_INC,
        Instruction_JMP,
        Instruction_LAC,
        Instruction_LAS,
        Instruction_LAT,
        Instruction_LDDX,
        Instruction_LDDXminus,
        Instruction_LDDXplus,
        Instruction_LDDY,
        Instruction_LDDYminus,
        Instruction_LDDYplus,
        Instruction_LDDYq,
        Instruction_LDDZ,
        Instruction_LDDZminus,
        Instruction_LDDZplus,
        Instruction_LDDZq,
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
        # TODO SBRC
        # TODO SBRS
        #SEC Virtual;
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
        Instruction_ST,
        Instruction_STplus,
        Instruction_STminus,
        # TODO: STDX
        # TODO: STDY
        # TODO: STDZ
        # TODO: STS
        # TODO: SUB
        # TODO: SUBI
        # TODO: SWAP
        Instruction_SUB,
        Instruction_SUBI,
        # TST Virtual; see AND
        Instruction_WDR,
        # TODO: XCH
        }



register(LifterAVR)

if __name__ == '__main__':
    import logging
    logging.basicConfig()
    logging.getLogger().setLevel(logging.DEBUG)
    tests = [
        b'\x00\x00',  # NOP
        b'\x23\x01',  # MOVW
        b'\x46\x02',  # MULS
    ]
    print "Decoder test:"
    for num, test in enumerate(tests):
        print num
        irsb_ = pyvex.IRSB(None, 0, arch=archinfo.ArchAVR())
        LifterAVR(irsb_, test, len(test), len(test), 0, None).lift()

    print "Lifter test:"
    for test2 in tests:
        irsb_ = pyvex.IRSB(None, 0, arch=archinfo.ArchAVR())
        l = LifterAVR(irsb_, test2, len(test2), len(test2), 0, None)
        l.lift()
        l.irsb.pp()

    print "Full tests:"
    fulltest = "".join(tests)
    irsb_ = pyvex.IRSB(None, 0, arch=archinfo.ArchAVR())
    l = LifterAVR(irsb_, fulltest, len(fulltest), len(fulltest), 0, None)
    l.lift()
    l.irsb.pp()
    pyvex.IRSB(fulltest, 0x0, arch=ArchAVR()).pp()
