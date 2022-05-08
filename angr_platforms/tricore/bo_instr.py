#!/usr/bin/env python3
""" bo_instr.py
Implementation of tricore BO format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import reverse16, extend_to_32_bits
from .logger import log_this


class BO_LD_09_Instructions(Instruction):
    """ A class for LOAD instruction with OP=09 """
    name = 'BO_LD_09_Instructions ...'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin).zfill(12))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x0:
            self.name = 'BO_LD.B_PostInc'
        elif op2 == 0x1:
            self.name = 'BO_LD.BU_PostInc'
        elif op2 == 0x2:
            self.name = 'BO_LD.H_PostInc'
        elif op2 == 0x3:
            self.name = 'BO_LD.HU_PostInc'
        elif op2 == 0x4:
            self.name = 'BO_LD.W_PostInc'
        elif op2 == 0x5:
            self.name = 'BO_LD.D_PostInc'
        elif op2 == 0x6:
            self.name = 'BO_LD.A_PostInc'
        elif op2 == 0x7:
            self.name = 'BO_LD.DA_PostInc'
        elif op2 == 0x8:
            self.name = 'BO_LD.Q_PostInc'
        elif op2 == 0x10:
            self.name = 'BO_LD.B_PreInc'
        elif op2 == 0x11:
            self.name = 'BO_LD.BU_PreInc'
        elif op2 == 0x12:
            self.name = 'BO_LD.H_PreInc'
        elif op2 == 0x13:
            self.name = 'BO_LD.HU_PreInc'
        elif op2 == 0x14:
            self.name = 'BO_LD.W_PreInc'
        elif op2 == 0x15:
            self.name = 'BO_LD.D_PreInc'
        elif op2 == 0x16:
            self.name = 'BO_LD.A_PreInc'
        elif op2 == 0x17:
            self.name = 'BO_LD.DA_PreInc'
        elif op2 == 0x18:
            self.name = 'BO_LD.Q_PreInc'
        elif op2 == 0x20:
            self.name = 'BO_LD.B_BaseShortOffset'
        elif op2 == 0x21:
            self.name = 'BO_LD.BU_BaseShortOffset'
        elif op2 == 0x22:
            self.name = 'BO_LD.H_BaseShortOffset'
        elif op2 == 0x23:
            self.name = 'BO_LD.HU_BaseShortOffset'
        elif op2 == 0x24:
            self.name = 'BO_LD.W_BaseShortOffset'
        elif op2 == 0x25:
            self.name = 'BO_LD.D_BaseShortOffset'
        elif op2 == 0x26:
            self.name = 'BO_LD.A_BaseShortOffset'
        elif op2 == 0x27:
            self.name = 'BO_LD.DA_BaseShortOffset'
        elif op2 == 0x28:
            self.name = 'BO_LD.Q_BaseShortOffset'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off10": int(off10.hex, 16),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_sign_ext_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        sign_ext_offset = args[1]
        result = ""
        op2 = self.data['op2']
        if op2 == 0x0:  # BO_LD.B_PostInc
            ea = a_b
            result = self.load(ea, Type.int_8).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x1:  # BO_LD.BU_PostInc
            ea = a_b
            result = self.load(ea, Type.int_8).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x2:  # BO_LD.H_PostInc
            ea = a_b
            result = self.load(ea, Type.int_16).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x3:  # BO_LD.HU_PostInc
            ea = a_b
            result = self.load(ea, Type.int_16).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x4:  # BO_LD.W_PostInc
            ea = a_b
            result = self.load(ea, Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x5:  # BO_LD.D_PostInc
            ea = a_b
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "d{0}".format(self.data['a']))
            self.put(result_1, "d{0}".format(self.data['a']+1))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x6:  # BO_LD.A_PostInc
            ea = a_b
            result = self.load(ea, Type.int_32)
            self.put(result, "a{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x7:  # BO_LD.DA_PostInc
            ea = a_b
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "a{0}".format(self.data['a']))
            self.put(result_1, "a{0}".format(self.data['a']+1))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x8:  # BO_LD.Q_PostInc
            ea = a_b
            result = self.load(ea, Type.int_16).cast_to(Type.int_32) << 16
            self.put(result, "d{0}".format(self.data['a']))
            result_2 = ea + sign_ext_offset  # increment
            self.put(result_2, "a{0}".format(self.data['b']))

        elif op2 == 0x10:  # BO_LD.B_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_8).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x11:  # BO_LD.BU_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_8).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x12:  # BO_LD.H_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x13:  # BO_LD.HU_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x14:  # BO_LD.W_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x15:  # BO_LD.D_PreInc
            ea = a_b + sign_ext_offset
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "d{0}".format(self.data['a']))
            self.put(result_1, "d{0}".format(self.data['a']+1))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x16:  # BO_LD.A_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_32)
            self.put(result, "a{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x17:  # BO_LD.DA_PreInc
            ea = a_b + sign_ext_offset
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "a{0}".format(self.data['a']))
            self.put(result_1, "a{0}".format(self.data['a']+1))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x18:  # BO_LD.Q_PreInc
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32) << 16
            self.put(result, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x20:  # BO_LD.B_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_8).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))

        elif op2 == 0x21:  # BO_LD.BU_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_8).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))

        elif op2 == 0x22:  # BO_LD.H_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32, signed=True)
            self.put(result, "d{0}".format(self.data['a']))

        elif op2 == 0x23:  # BO_LD.HU_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))

        elif op2 == 0x24:  # BO_LD.W_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_32)
            self.put(result, "d{0}".format(self.data['a']))

        elif op2 == 0x25:  # BO_LD.D_BaseShortOffset
            ea = a_b + sign_ext_offset
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "d{0}".format(self.data['a']))
            self.put(result_1, "d{0}".format(self.data['a']+1))

        elif op2 == 0x26:  # BO_LD.A_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_32)
            self.put(result, "a{0}".format(self.data['a']))

        elif op2 == 0x27:  # BO_LD.DA_BaseShortOffset
            ea = a_b + sign_ext_offset
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "a{0}".format(self.data['a']))
            self.put(result_1, "a{0}".format(self.data['a']+1))

        elif op2 == 0x28:  # BO_LD.Q_BaseShortOffset
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_16).cast_to(Type.int_32) << 16
            self.put(result, "d{0}".format(self.data['a']))

class BO_LD_29_Instructions(Instruction):
    """ A class for LOAD instructions with OP=29 """
    name = 'BO_LD_29_Instructions ...'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x0:
            self.name = 'BO_LD.B_BitRev'
        elif op2 == 0x1:
            self.name = 'BO_LD.BU_BitRev'
        elif op2 == 0x2:
            self.name = 'BO_LD.H_BitRev'
        elif op2 == 0x3:
            self.name = 'BO_LD.HU_BitRev'
        elif op2 == 0x4:
            self.name = 'BO_LD.W_BitRev'
        elif op2 == 0x5:
            self.name = 'BO_LD.D_BitRev'
        elif op2 == 0x6:
            self.name = 'BO_LD.A_BitRev'
        elif op2 == 0x7:
            self.name = 'BO_LD.DA_BitRev'
        elif op2 == 0x8:
            self.name = 'BO_LD.Q_BitRev'
        elif op2 == 0x10:
            self.name = 'BO_LD.B_Circ'
        elif op2 == 0x11:
            self.name = 'BO_LD.BU_Circ'
        elif op2 == 0x12:
            self.name = 'BO_LD.H_Circ'
        elif op2 == 0x13:
            self.name = 'BO_LD.HU_Circ'
        elif op2 == 0x14:
            self.name = 'BO_LD.W_Circ'
        elif op2 == 0x15:
            self.name = 'BO_LD.D_Circ'
        elif op2 == 0x16:
            self.name = 'BO_LD.A_Circ'
        elif op2 == 0x17:
            self.name = 'BO_LD.DA_Circ'
        elif op2 == 0x18:
            self.name = 'BO_LD.Q_Circ'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off10": int(off10.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        if self.data['op2'] in ["0x6", "0x16"]:
            return "a{0}".format(self.data['a'])
        return "d{0}".format(self.data['a'])

    def get_sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    def get_a_b_1(self):
        return self.get("a{0}".format(self.data['b']+1), Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_a_b_1(), self.get_sign_ext_offset()

    def compute_result(self, *args):
        a_b = args[0]
        a_b_1 = args[1]
        sign_ext_offset = args[2]
        result = ""
        op2 = self.data['op2']
        if op2 == 0x0:  # BO_LD.B_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_8).cast_to(Type.int_32, signed=True)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        if op2 == 0x1:  # BO_LD.BU_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_8)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x2:  # BO_LD.H_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16).cast_to(Type.int_32, signed=True)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x3:  # BO_LD.HU_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x4:  # BO_LD.W_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_32)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x5:  # BO_LD.D_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "d{0}".format(self.data['a']))
            self.put(result_1, "d{0}".format(self.data['a']+1))
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x6:  # BO_LD.A_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_32)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x7:  # BO_LD.DA_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result_0 = self.load(ea, Type.int_32)
            result_1 = self.load(ea+4, Type.int_32)
            self.put(result_0, "a{0}".format(self.data['a']))
            self.put(result_1, "a{0}".format(self.data['a']+1))
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x8:  # BO_LD.Q_BitRev
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16).cast_to(Type.int_32) << 16
            new_index = reverse16(reverse16(index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x10:  # BO_LD.B_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_8).cast_to(Type.int_32, signed=True)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x11:  # BO_LD.BU_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_8)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x12:  # BO_LD.H_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16).cast_to(Type.int_32, signed=True)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x13:  # BO_LD.HU_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x14:  # BO_LD.W_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea_0 = a_b + index
            ea_2 = a_b + index + (2 % length)
            result = self.load(ea_2, Type.int_16).cast_to(Type.int_32) << 16 | \
                     self.load(ea_0, Type.int_16).cast_to(Type.int_32)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x15:  # BO_LD.D_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea_0 = a_b + index
            ea_2 = a_b + (index + 2) % length
            ea_4 = a_b + (index + 4) % length
            ea_6 = a_b + (index + 6) % length
            result_hw0 = self.load(ea_0, Type.int_16).cast_to(Type.int_32)
            result_hw1 = self.load(ea_2, Type.int_16).cast_to(Type.int_32)
            result_hw2 = self.load(ea_4, Type.int_16).cast_to(Type.int_32)
            result_hw3 = self.load(ea_6, Type.int_16).cast_to(Type.int_32)
            result_0 = (result_hw1 << 16) | result_hw0
            result_1 = (result_hw3 << 16) | result_hw2
            self.put(result_0, "d{0}".format(self.data['a']))
            self.put(result_1, "d{0}".format(self.data['a']+1))
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x16:  # BO_LD.A_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_32)
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x17:  # BO_LD.DA_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea_0 = a_b + index
            ea_4 = a_b + (index + 4) % length
            result_0 = self.load(ea_0, Type.int_32)
            result_1 = self.load(ea_4, Type.int_32)
            self.put(result_0, "a{0}".format(self.data['a']))
            self.put(result_1, "a{0}".format(self.data['a']+1))
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x18:  # BO_LD.Q_Circ
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_16).cast_to(Type.int_32) << 16
            new_index = index + sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + length) & cond_new_index_neg) | \
                        ((new_index % length) & (cond_new_index_neg^0xffffffff))
            result_2 = ((length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BO_49_Instructions(Instruction):
    """ A class for instructions with OP=49 """
    name = 'BO_49_Instructions ...'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin).zfill(12))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x0:
            self.name = 'BO_SWAP.W (Post-increment Addressing Mode)'
        elif op2 == 0x1:
            self.name = 'BO_LDMST (Post-increment Addressing Mode)'
        elif op2 == 0x10:
            self.name = 'BO_SWAP.W (Pre-increment Addressing Mode)'
        elif op2 == 0x11:
            self.name = 'BO_LDMST (Pre-increment Addressing Mode)'
        elif op2 == 0x20:
            self.name = 'BO_SWAP.W (Base + Short Offset Addressing Mode)'
        elif op2 == 0x21:
            self.name = 'BO_LDMST (Base + Short Offset Addressing Mode)'
        elif op2 == 0x24:
            self.name = 'BO_LDLCX'
        elif op2 == 0x25:
            self.name = 'BO_LDUCX'
        elif op2 == 0x26:
            self.name = 'BO_STLCX'
        elif op2 == 0x27:
            self.name = 'BO_STUCX'
        elif op2 == 0x28:
            self.name = 'BO_LEA'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off10": int(off10.hex, 16),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_sign_ext_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        sign_ext_offset = args[1]
        result = ""
        op2 = self.data['op2']
        if op2 == 0x0:  # SWAP.W (Post-increment Addressing Mode)
            ea = a_b
            tmp = self.load(ea, Type.int_32)
            self.store(self.get("d{0}".format(self.data['a']), Type.int_32), ea)
            self.put(tmp, "d{0}".format(self.data['a']))
            self.put(ea + sign_ext_offset, "a{0}".format(self.data['b']))

        elif op2 == 0x1:  # LDMST (Post-increment Addressing Mode)
            ea = a_b
            result = self.load(ea, Type.int_32)
            e_a_1 = self.get("d{0}".format(self.data['a']), Type.int_32)    # E[a][31:0]
            e_a_2 = self.get("d{0}".format(self.data['a']+1), Type.int_32)  # E[a][63:32]
            result = (result & ~e_a_2) | (e_a_1 & e_a_2)
            self.store(result, ea)
            self.put(ea + sign_ext_offset, "a{0}".format(self.data['b']))

        elif op2 == 0x10:  # SWAP.W (Pre-increment Addressing Mode)
            tmp = self.load(ea, Type.int_32)
            self.store(self.get("d{0}".format(self.data['a']), Type.int_32), ea)
            self.put(tmp, "d{0}".format(self.data['a']))
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x11:  # LDMST (Pre-increment Addressing Mode)
            result = self.load(ea, Type.int_32)
            e_a_1 = self.get("d{0}".format(self.data['a']), Type.int_32)    # E[a][31:0]
            e_a_2 = self.get("d{0}".format(self.data['a']+1), Type.int_32)  # E[a][63:32]
            result = (result & ~e_a_2) | (e_a_1 & e_a_2)
            self.store(result, ea)
            self.put(ea, "a{0}".format(self.data['b']))

        elif op2 == 0x20:  # SWAP.W (Base + Short Offset Addressing Mode)
            tmp = self.load(ea, Type.int_32)
            self.store(self.get("d{0}".format(self.data['a']), Type.int_32), ea)
            self.put(self.load(ea, Type.int_32), "a{0}".format(self.data['a']))
            self.put(tmp, "d{0}".format(self.data['a']))

        elif op2 == 0x21:  # LDMST (Base + Short Offset Addressing Mode)
            ea = a_b + sign_ext_offset
            result = self.load(ea, Type.int_32)
            e_a_1 = self.get("d{0}".format(self.data['a']), Type.int_32)    # E[a][31:0]
            e_a_2 = self.get("d{0}".format(self.data['a']+1), Type.int_32)  # E[a][63:32]
            result = (result & ~e_a_2) | (e_a_1 & e_a_2)
            self.store(result, ea)

        elif op2 == 0x24:  # LDLCX
            #dummy = self.load(ea, Type.int_32)
            #dummy = self.load(ea+4, Type.int_32)
            self.put(self.load(ea+8, Type.int_32), "a2")
            self.put(self.load(ea+12, Type.int_32), "a3")
            self.put(self.load(ea+16, Type.int_32), "d0")
            self.put(self.load(ea+20, Type.int_32), "d1")
            self.put(self.load(ea+24, Type.int_32), "d2")
            self.put(self.load(ea+28, Type.int_32), "d3")
            self.put(self.load(ea+32, Type.int_32), "a4")
            self.put(self.load(ea+36, Type.int_32), "a5")
            self.put(self.load(ea+40, Type.int_32), "a6")
            self.put(self.load(ea+44, Type.int_32), "a7")
            self.put(self.load(ea+48, Type.int_32), "d4")
            self.put(self.load(ea+52, Type.int_32), "d5")
            self.put(self.load(ea+56, Type.int_32), "d6")
            self.put(self.load(ea+60, Type.int_32), "d7")

        elif op2 == 0x25:  # LDUCX
            #dummy = self.load(ea, Type.int_32)
            #dummy = self.load(ea+4, Type.int_32)
            self.put(self.load(ea+8, Type.int_32), "a10")
            self.put(self.load(ea+12, Type.int_32), "a11")
            self.put(self.load(ea+16, Type.int_32), "d8")
            self.put(self.load(ea+20, Type.int_32), "d9")
            self.put(self.load(ea+24, Type.int_32), "d10")
            self.put(self.load(ea+28, Type.int_32), "d11")
            self.put(self.load(ea+32, Type.int_32), "a12")
            self.put(self.load(ea+36, Type.int_32), "a13")
            self.put(self.load(ea+40, Type.int_32), "a14")
            self.put(self.load(ea+44, Type.int_32), "a15")
            self.put(self.load(ea+48, Type.int_32), "d12")
            self.put(self.load(ea+52, Type.int_32), "d13")
            self.put(self.load(ea+56, Type.int_32), "d14")
            self.put(self.load(ea+60, Type.int_32), "d15")

        elif op2 == 0x26:  # STLCX
            self.store(self.get("pcxi", Type.int_32), ea)
            self.store(self.get("a11", Type.int_32), ea+4)
            self.store(self.get("a2", Type.int_32), ea+8)
            self.store(self.get("a3", Type.int_32), ea+12)
            self.store(self.get("d0", Type.int_32), ea+16)
            self.store(self.get("d1", Type.int_32), ea+20)
            self.store(self.get("d2", Type.int_32), ea+24)
            self.store(self.get("d3", Type.int_32), ea+28)
            self.store(self.get("a4", Type.int_32), ea+32)
            self.store(self.get("a5", Type.int_32), ea+36)
            self.store(self.get("a6", Type.int_32), ea+40)
            self.store(self.get("a7", Type.int_32), ea+44)
            self.store(self.get("d4", Type.int_32), ea+48)
            self.store(self.get("d5", Type.int_32), ea+52)
            self.store(self.get("d6", Type.int_32), ea+56)
            self.store(self.get("d7", Type.int_32), ea+60)

        elif op2 == 0x27:  # STUCX
            self.store(self.get("pcxi", Type.int_32), ea)
            self.store(self.get("psw", Type.int_32), ea+4)
            self.store(self.get("a10", Type.int_32), ea+8)
            self.store(self.get("a11", Type.int_32), ea+12)
            self.store(self.get("d8", Type.int_32), ea+16)
            self.store(self.get("d9", Type.int_32), ea+20)
            self.store(self.get("d10", Type.int_32), ea+24)
            self.store(self.get("d11", Type.int_32), ea+28)
            self.store(self.get("a12", Type.int_32), ea+32)
            self.store(self.get("a13", Type.int_32), ea+36)
            self.store(self.get("a14", Type.int_32), ea+40)
            self.store(self.get("a15", Type.int_32), ea+44)
            self.store(self.get("d12", Type.int_32), ea+48)
            self.store(self.get("d13", Type.int_32), ea+52)
            self.store(self.get("d14", Type.int_32), ea+56)
            self.store(self.get("d15", Type.int_32), ea+60)

        elif op2 == 0x28:  # LEA
            ea = a_b + sign_ext_offset
            self.put(ea, "a{0}".format(self.data["a"]))

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BO instruction OP=49, OP2=Unknown")
            sys.exit(1)

class BO_69_Instructions(Instruction):
    """ A class for instructions with OP=69 """
    name = 'BO_69_Instructions ...'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin).zfill(12))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x0:
            self.name = 'BO_SWAP.W (Bit-reverse Addressing Mode)'
        elif op2 == 0x1:
            self.name = 'BO_LDMST (Bit-reverse Addressing Mode)'
        elif op2 == 0x10:
            self.name = 'BO_SWAP.W (Circular Addressing Mode)'
        elif op2 == 0x11:
            self.name = 'BO_LDMST (Circular Addressing Mode)'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off10": int(off10.hex, 16),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_b_1(self):
        return self.get("a{0}".format(self.data['b']+1), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_a_b_1(), self.get_sign_ext_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        a_b_1 = args[1]
        sign_ext_offset = args[2]
        result = ""
        op2 = self.data['op2']
        if op2 == 0x0:  # SWAP.W (Bit-reverse Addressing Mode)
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            tmp = self.load(ea, Type.int_32)
            self.store("d{0}".format(self.data['a']), ea)
            self.put(tmp, "d{0}".format(self.data['a']))
            new_index = reverse16(reverse16(index) + reverse16(incr))
            self.put(((incr & 0xffff) << 16) | (new_index & 0xffff), "a{0}".format(self.data['b']+1))

        elif op2 == 0x1:  # LDMST (Bit-reverse Addressing Mode)
            index = a_b_1 & 0xffff
            incr = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_32)
            e_a_1 = self.get("d{0}".format(self.data['a']), Type.int_32)    # E[a][31:0]
            e_a_2 = self.get("d{0}".format(self.data['a']+1), Type.int_32)  # E[a][63:32]
            result = (result & ~e_a_2) | (e_a_1 & e_a_2)
            self.store(result, ea)
            new_index = reverse16(reverse16(index) + reverse16(incr))
            self.put(((incr & 0xffff) << 16) | (new_index & 0xffff), "a{0}".format(self.data['b']+1))

        elif op2 == 0x10:  # SWAP.W (Circular Addressing Mode)
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            tmp = self.load(ea, Type.int_32)
            self.store("d{0}".format(self.data['a']), ea)
            self.put(tmp, "d{0}".format(self.data['a']))
            new_index = index + sign_ext_offset
            new_index = (new_index < 0).ite(
                new_index + length,
                new_index % length
            )
            self.put(((length & 0xffff) << 16) | (new_index & 0xffff), "a{0}".format(self.data['b']+1))

        elif op2 == 0x11:  # LDMST (Circular Addressing Mode)
            index = a_b_1 & 0xffff
            length = a_b_1 >> 16
            ea = a_b + index
            result = self.load(ea, Type.int_32)
            e_a_1 = self.get("d{0}".format(self.data['a']), Type.int_32)    # E[a][31:0]
            e_a_2 = self.get("d{0}".format(self.data['a']+1), Type.int_32)  # E[a][63:32]
            result = (result & ~e_a_2) | (e_a_1 & e_a_2)
            self.store(result, ea)
            new_index = index + sign_ext_offset
            new_index = (new_index < 0).ite(
                new_index + length,
                new_index % length
            )
            self.put(((length & 0xffff) << 16) | (new_index & 0xffff), "a{0}".format(self.data['b']+1))

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BO instruction OP=69, OP2=Unknown")
            sys.exit(1)

class BO_ST_89_Instructions(Instruction):
    """ A class for STORE instructions with OP=89 """
    name = 'BO_ST_89_Instructions ...'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x6:
            self.name = 'BO_ST.A_PostInc'
        elif op2 == 0x16:
            self.name = 'BO_ST.A_PreInc'
        elif op2 == 0x26:
            self.name = 'BO_ST.A_BaseShortOffset'
        elif op2 == 0x0:
            self.name = 'BO_ST.B_PostInc'
        elif op2 == 0x10:
            self.name = 'BO_ST.B_PreInc'
        elif op2 == 0x20:
            self.name = 'BO_ST.B_BaseShortOffset'
        elif op2 == 0x2:
            self.name = 'BO_ST.H_PostInc'
        elif op2 == 0x12:
            self.name = 'BO_ST.H_PreInc'
        elif op2 == 0x22:
            self.name = 'BO_ST.H_BaseShortOffset'
        elif op2 == 0x4:
            self.name = 'BO_ST.W_PostInc'
        elif op2 == 0x14:
            self.name = 'BO_ST.W_PreInc'
        elif op2 == 0x24:
            self.name = 'BO_ST.W_BaseShortOffset'
        elif op2 == 0x5:
            self.name = 'BO_ST.D_PostInc'
        elif op2 == 0x15:
            self.name = 'BO_ST.D_PreInc'
        elif op2 == 0x25:
            self.name = 'BO_ST.D_BaseShortOffset'
        elif op2 == 0x7:
            self.name = 'BO_ST.DA_PostInc'
        elif op2 == 0x17:
            self.name = 'BO_ST.DA_PreInc'
        elif op2 == 0x27:
            self.name = 'BO_ST.DA_BaseShortOffset'
        elif op2 == 0x8:
            self.name = 'BO_ST.Q_PostInc'
        elif op2 == 0x18:
            self.name = 'BO_ST.Q_PreInc'
        elif op2 == 0x28:
            self.name = 'BO_ST.Q_BaseShortOffset'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "off10": int(off10.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def ea(self):
        """ Return A[b]+ off10. """
        return self.a_b + self.sign_ext_offset

    @property
    def sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    @property
    def a_b(self):
        """ Return A[b] register. """
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    @property
    def a_a_1(self):
        """ Return A[a]+1 register. """
        return self.get("a{0}".format(self.data['a']+1), Type.int_32)

    @property
    def a_a(self):
        """ Return A[a] register. """
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    @property
    def d_a_1(self):
        """ Return D[a]+1 register. """
        return self.get("d{0}".format(self.data['a']+1), Type.int_32)

    @property
    def d_a(self):
        """ Return D[a] register """
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def compute_result(self, *args):
        op2 = self.data['op2']
        if op2 == 0x6:  # BO_ST.A_PostInc
            self.store(self.a_a, self.a_b)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x16:  # BO_ST.A_PreInc
            self.store(self.a_a, self.ea)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x26:  # BO_ST.A_BaseShortOffset
            self.store(self.a_a, self.ea)

        elif op2 == 0x0:  # BO_ST.B_PostInc
            val = self.d_a & 0xff
            self.store(val, self.a_b)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x10:  # BO_ST.B_PreInc
            val = self.d_a & 0xff
            self.store(val, self.ea)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x20:  # BO_ST.B_BaseShortOffset
            val = self.d_a & 0xff
            self.store(val, self.ea)

        elif op2 == 0x2:  # BO_ST.H_PostInc
            val = self.d_a & 0xffff
            self.store(val, self.a_b)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x12:  # BO_ST.H_PreInc
            val = self.d_a & 0xffff
            self.store(val, self.ea)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x22:  # BO_ST.H_BaseShortOffset
            val = self.d_a & 0xffff
            self.store(val, self.ea)

        elif op2 == 0x4:  # BO_ST.W_PostInc
            val = self.d_a
            self.store(val, self.a_b)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x14:  # BO_ST.W_PreInc
            self.store(self.d_a, self.ea)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x24:  # BO_ST.W_BaseShortOffset
            self.store(self.d_a, self.ea)

        elif op2 == 0x5:  # BO_ST.D_PostInc
            self.store(self.d_a, self.a_b)
            self.store(self.d_a_1, self.a_b+4)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x15:  # BO_ST.D_PreInc
            self.store(self.d_a, self.ea)
            self.store(self.d_a_1, self.ea+4)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x25:  # BO_ST.D_BaseShortOffset
            self.store(self.d_a, self.ea)
            self.store(self.d_a_1, self.ea+4)

        elif op2 == 0x7:  # BO_ST.DA_PostInc
            self.store(self.a_a, self.a_b)
            self.store(self.a_a_1, self.a_b+4)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x17:  # BO_ST.DA_PreInc
            self.store(self.a_a, self.ea)
            self.store(self.a_a_1, self.ea+4)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x27:  # BO_ST.DA_BaseShortOffset
            self.store(self.a_a, self.ea)
            self.store(self.a_a_1, self.ea+4)

        elif op2 == 0x8:  # BO_ST.Q_PostInc
            val = self.d_a >> 16
            self.store(val, self.a_b)
            inc = self.a_b + self.sign_ext_offset
            self.put(inc, "a{0}".format(self.data['b']))

        elif op2 == 0x18:  # BO_ST.Q_PreInc
            val = self.d_a >> 16
            self.store(val, self.ea)
            self.put(self.ea, "a{0}".format(self.data['b']))

        elif op2 == 0x28:  # BO_ST.Q_BaseShortOffset
            val = self.d_a >> 16
            self.store(val, self.ea)

        else:
            print("Error: Unknown OP2 '{0}'!".format(op2))
            print("BO instruction OP=89, OP2=Unknown")
            sys.exit(1)

class BO_ST_A9_Instructions(Instruction):
    """ A class for STORE instructions with OP=A9 """
    name = 'BO_ST_A9_Instructions ...'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off10 = bitstring.BitArray(bin="{0}{1}".format(tmp[0:4].bin,
                                                       tmp[10:16].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:10]))
        op2 = int(op2.bin, 2)
        b = tmp[16:20]
        a = tmp[20:]

        if op2 == 0x0:
            self.name = 'BO_ST.B_BitRev'
        elif op2 == 0x10:
            self.name = 'BO_ST.B_Circ'
        elif op2 == 0x5:
            self.name = 'BO_ST.D_BitRev'
        elif op2 == 0x15:
            self.name = 'BO_ST.D_Circ'
        elif op2 == 0x6:
            self.name = 'BO_ST.A_BitRev'
        elif op2 == 0x16:
            self.name = 'BO_ST.A_Circ'
        elif op2 == 0x7:
            self.name = 'BO_ST.DA_BitRev'
        elif op2 == 0x17:
            self.name = 'BO_ST.DA_Circ'
        elif op2 == 0x2:
            self.name = 'BO_ST.H_BitRev'
        elif op2 == 0x12:
            self.name = 'BO_ST.H_Circ'
        elif op2 == 0x8:
            self.name = 'BO_ST.Q_BitRev'
        elif op2 == 0x18:
            self.name = 'BO_ST.Q_Circ'
        elif op2 == 0x4:
            self.name = 'BO_ST.W_BitRev'
        elif op2 == 0x14:
            self.name = 'BO_ST.W_Circ'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off10": int(off10.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def index(self):
        return self.a_b_1 & 0xffff

    @property
    def length(self):
        return self.a_b_1 >> 16

    @property
    def ea_6(self):
        return self.a_b + ((self.index+6) % self.length)

    @property
    def ea_4(self):
        return self.a_b + ((self.index+4) % self.length)

    @property
    def ea_2(self):
        return self.a_b + ((self.index+2) % self.length)

    @property
    def ea_0(self):
        return self.a_b + self.index

    @property
    def sign_ext_offset(self):
        return self.constant(self.data['off10'], Type.int_10).cast_to(Type.int_32, signed=True)

    @property
    def a_b_1(self):
        return self.get("a{0}".format(self.data['b']+1), Type.int_32)

    @property
    def a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    @property
    def a_a_1(self):
        return self.get("a{0}".format(self.data['a']+1), Type.int_32)

    @property
    def a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    @property
    def d_a_1(self):
        return self.get("d{0}".format(self.data['a']+1), Type.int_32)

    @property
    def d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def compute_result(self, *args):
        op2 = self.data['op2']
        if op2 == 0x0:  # BO_ST.B_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.d_a & 0xff, self.ea_0)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x10:  # BO_ST.B_Circ
            self.store(self.d_a & 0xff, self.ea_0)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x5:  # BO_ST.D_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.d_a, self.ea_0)
            self.store(self.d_a_1, self.ea_0+4)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x15:  # BO_ST.D_Circ
            self.store(self.d_a & 0xffff, self.ea_0)
            self.store(self.d_a >> 16, self.ea_2)
            self.store(self.d_a_1 & 0xffff, self.ea_4)
            self.store(self.d_a_1 >> 16, self.ea_6)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x6:  # BO_ST.A_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.a_a, self.ea_0)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x16:  # BO_ST.A_Circ
            self.store(self.a_a, self.ea_0)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x7:  # BO_ST.DA_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.a_a, self.ea_0)
            self.store(self.a_a_1, self.ea_0+4)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x17:  # BO_ST.DA_Circ
            self.store(self.a_a, self.ea_0)
            self.store(self.a_a_1, self.ea_4)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x2:  # BO_ST.H_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.d_a & 0xffff, self.ea_0)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x12:  # BO_ST.H_Circ
            self.store(self.d_a & 0xffff, self.ea_0)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x8:  # BO_ST.Q_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.d_a >> 16, self.ea_0)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x18:  # BO_ST.Q_Circ
            self.store(self.d_a >> 16, self.ea_0)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        elif op2 == 0x4:  # BO_ST.W_BitRev
            incr = self.a_b_1 >> 16
            self.store(self.d_a, self.ea_0)
            new_index = reverse16(reverse16(self.index) + reverse16(incr))
            result_2 = ((incr & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result_2, "a{0}".format(self.data['b']+1))

        elif op2 == 0x14:  # BO_ST.W_Circ
            self.store(self.d_a, self.ea_0)
            new_index = self.index + self.sign_ext_offset
            cond_new_index_neg = extend_to_32_bits(new_index & 0x80000000 == 0x80000000)
            new_index = ((new_index + self.length) & cond_new_index_neg) | \
                        ((new_index % self.length) & (cond_new_index_neg^0xffffffff))
            result = ((self.length & 0xffff) << 16) | (new_index & 0xffff)
            self.put(result, "a{0}".format(self.data['b']+1))

        else:
            print("Error: Unknown OP2 '{0}'!".format(op2))
            print("BO instruction OP=A9, OP2=Unknown")
            sys.exit(1)
