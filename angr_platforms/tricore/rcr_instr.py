#!/usr/bin/env python3
""" rcr_instr.py
Implementation of RCR format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RCR_Instructions_OP_AB(Instruction):
    """ RCR instructions with OP=AB.
        - Conditional Add:
            op = 0xAB
            op2 = 0x00
            User Status Flags: V, SV, AV, SAV
        - Conditional Add-Not:
            op = 0xAB
            op2 = 0x01
            User Status Flags: V, SV, AV, SAV
        - Select:
            op = 0xAB
            op2 = 0x04
            User Status Flags: no change.
        - Select-Not:
            op = 0xAB
            op2 = 0x05
            User Status Flags: no change.
    """
    name = 'RCR_Instructions_OP_AB ...'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[8:11].bin))
        op2 = int(op2.bin, 2)
        d = tmp[4:8]
        c = tmp[:4]

        if op2 == 0:
            self.name = "RCR_CADD"
        elif op2 == 1:
            self.name = "RCR_CADDN"
        elif op2 == 4:
            self.name = "RCR_SEL"
        elif op2 == 5:
            self.name = "RCR_SELN"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "const9": int(const9.bin, 2),
                "op2": op2,
                "c": int(c.bin, 2),
                "d": int(d.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const9_sign_ext(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32, signed=True)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d(), self.get_const9_sign_ext()

    def compute_result(self, *args):
        d_a = args[0]
        d_d = args[1]
        const9_sign_ext = args[2]
        result = ""
        if self.data['op2'] == 0x0:  # CADD
            condition = extend_to_32_bits(d_d != 0)
            result = ((d_a + const9_sign_ext) & condition) | (d_a & ~condition)

        elif self.data['op2'] == 0x1:  # CADDN
            condition = extend_to_32_bits(d_d == 0)
            result = ((d_a + const9_sign_ext) & condition) | (d_a & ~condition)

        elif self.data['op2'] == 0x4:  # SEL
            condition = extend_to_32_bits(d_d != 0)
            result = (d_a & condition) | (const9_sign_ext & ~condition)
            return result  # no change in flags, so return here

        elif self.data['op2'] == 0x5:  # SELN
            condition = extend_to_32_bits(d_d == 0)
            result = (d_a & condition) | (const9_sign_ext & ~condition)
            return result  # no change in flags, so return here

        c = 0
        v = (result >> 32 != 0)
        sv = 0
        av = result[31] ^ result[30]
        sav = 0
        psw = self.get_psw()
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RCR_Instructions_OP_13(Instruction):
    """ RCR instructions with OP=13:
        - Multiply-Add (32-bit):
            op = 0x13
            op2 = 0x01 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add (64-bit):
            op = 0x13
            op2 = 0x03 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add Unsigned:
            op = 0x13
            op2 = 0x02 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add Unsigned, Saturated (32-bit):
            op = 0x13
            op2 = 0x04 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add, Saturated (32-bit):
            op = 0x13
            op2 = 0x05 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add Unsigned, Saturated (64-bit):
            op = 0x13
            op2 = 0x06 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Add, Saturated (64-bit):
            op = 0x13
            op2 = 0x07 (3 bits)
            User Status Flags: V, SV, AV, SAV
    """
    name = 'RCR_Instructions_OP_13 ...'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(3)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[8:11].bin))
        op2 = int(op2.bin, 2)
        d = tmp[4:8]
        c = tmp[:4]

        if op2 == 1:
            self.name = "RCR_MADD (32-bit)"
        elif op2 == 2:
            self.name = "RCR_MADD.U (64-bit)"
        elif op2 == 3:
            self.name = "RCR_MADD (64-bit)"
        elif op2 == 4:
            self.name = "RCR_MADDS.U (32-bit)"
        elif op2 == 5:
            self.name = "RCR_MADDS (32-bit)"
        elif op2 == 6:
            self.name = "RCR_MADDS.U (64-bit)"
        elif op2 == 7:
            self.name = "RCR_MADDS (64-bit)"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "const9": int(const9.bin, 2),
                "op2": op2,
                "c": int(c.bin, 2),
                "d": int(d.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT32_MAX_POS, Type.int_32)

    @property
    def max_neg(self):
        return self.constant(INT32_MAX_NEG, Type.int_32)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const9(self):
        return self.constant(self.data['const9'], Type.int_32)

    def get_const9_sign_ext(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32, signed=True)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d(), self.get_const9(), self.get_const9_sign_ext()

    def compute_result(self, *args):
        d_a = args[0]
        d_d = args[1]
        const9 = args[2]
        const9_sign_ext = args[3]
        result = ""
        if self.data['op2'] == 1:  # MADD (32-bit)
            result = d_d + (d_a * const9_sign_ext)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 2:  # MADD.U (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            d_a_64 = d_a.cast_to(Type.int_64) * const9.cast_to(Type.int_64)
            result = e_d + d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 3:  # MADD (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            const9_sign_ext_64bit = const9_sign_ext.cast_to(Type.int_64, signed=True)
            d_a_64 = d_a.cast_to(Type.int_64) * const9_sign_ext_64bit
            result = e_d + d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 4:  # MADDS.U (32-bit)
            result = suov32_sub(d_d + (d_a * const9))  # Unsigned
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 5:  # MADDS (32-bit)
            result = ssov32(d_d + (d_a * const9_sign_ext), self.max_pos, self.max_neg)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 6:  # MADDS.U (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            result_mul = d_a.cast_to(Type.int_64) * const9.cast_to(Type.int_64)
            result = suov64(e_d + result_mul)
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 7:  # MADDS (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            const9_sign_ext_64bit = const9_sign_ext.cast_to(Type.int_64, signed=True)
            d_a_64 = d_a.cast_to(Type.int_64) * const9_sign_ext_64bit
            result = ssov64(e_d + d_a_64)
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("RCR instruction OP=13, OP2=Unknown")
            sys.exit(1)

        # set flags
        c = 0
        if self.data['op2'] in [0x1, 0x4, 0x5]:  # 32-bit
            v = overflow(result)
            av = advanced_overflow(result)
        elif self.data['op2'] in [0x2, 0x3, 0x6, 0x7]:  # 64-bit
            v = overflow_64(result).cast_to(Type.int_32)
            av = advanced_overflow_64(result).cast_to(Type.int_32)
        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("RCR instruction OP=13, OP2=Unknown")
            sys.exit(1)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        s_overflow = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sa_overflow = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, s_overflow, av, sa_overflow)
        self.put(psw, "psw")

class RCR_Instructions_OP_33(Instruction):
    """ RCR instructions with OP=33:
        - Multiply-Subtract (32-bit):
            op = 0x33
            op2 = 0x01 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract Unsigned (32-bit):
            op = 0x33
            op2 = 0x02 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract (64-bit):
            op = 0x33
            op2 = 0x03 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract Unsigned, Saturated (32-bit):
            op = 0x33
            op2 = 0x04 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract, Saturated (32-bit):
            op = 0x33
            op2 = 0x05 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract, Saturated (64-bit):
            op = 0x33
            op2 = 0x06 (3 bits)
            User Status Flags: V, SV, AV, SAV
        - Multiply-Subtract, Saturated (64-bit):
            op = 0x33
            op2 = 0x07 (3 bits)
            User Status Flags: V, SV, AV, SAV
    """
    name = 'RCR_Instructions_OP_33 ...'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(3)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[8:11].bin))
        op2 = int(op2.bin, 2)
        d = tmp[4:8]
        c = tmp[:4]

        if op2 == 1:
            self.name = "RCR_MSUB (32-bit)"
        elif op2 == 2:
            self.name = "RCR_MSUB.U (64-bit)"
        elif op2 == 3:
            self.name = "RCR_MSUB (64-bit)"
        elif op2 == 4:
            self.name = "RCR_MSUBS.U (32-bit)"
        elif op2 == 5:
            self.name = "RCR_MSUBS (32-bit)"
        elif op2 == 6:
            self.name = "RCR_MSUBS.U (64-bit)"
        elif op2 == 7:
            self.name = "RCR_MSUBS (64-bit)"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "const9": int(const9.bin, 2),
                "op2": op2,
                "c": int(c.bin, 2),
                "d": int(d.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT32_MAX_POS, Type.int_32)

    @property
    def max_neg(self):
        return self.constant(INT32_MAX_NEG, Type.int_32)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const9(self):
        return self.constant(self.data['const9'], Type.int_32)

    def get_const9_sign_ext(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32, signed=True)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d(), self.get_const9(), self.get_const9_sign_ext()

    def compute_result(self, *args):
        d_a = args[0]
        d_d = args[1]
        const9 = args[2]
        const9_sign_ext = args[3]
        result = ""
        if self.data['op2'] == 1:  # MSUB (32-bit)
            result = d_d - (d_a * const9_sign_ext)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 2:  # MSUB.U (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            d_a_64 = d_a.cast_to(Type.int_64) * const9.cast_to(Type.int_64)
            result = e_d - d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 3:  # MSUB (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            d_a_64 = d_a.cast_to(Type.int_64) * const9_sign_ext.cast_to(Type.int_64, signed=True)
            result = e_d - d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 4:  # MSUBS.U (32-bit)
            result = suov32(d_d - (d_a * const9))
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 5:  # MSUBS (32-bit)
            result = ssov32(d_d - (d_a * const9_sign_ext), self.max_pos, self.max_neg)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 6:  # MSUBS.U (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            d_a_64 = d_a.cast_to(Type.int_64) * const9.cast_to(Type.int_64)
            result = e_d - d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        elif self.data['op2'] == 7:  # MSUBS (64-bit)
            d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
            d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
            e_d = self.constant(0, Type.int_64)  # 64-bit object
            e_d |= d_d_2.cast_to(Type.int_64)
            e_d <<= 32
            e_d |= d_d_1.cast_to(Type.int_64)
            d_a_64 = d_a.cast_to(Type.int_64) * const9_sign_ext.cast_to(Type.int_64, signed=True)
            result = e_d - d_a_64
            result_d_c_1 = result & 0xffffffff
            result_d_c_2 = result >> 32
            self.put(result_d_c_1, "d{0}".format(self.data['c']))
            self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("RCR instruction OP=33, OP2=Unknown")
            sys.exit(1)

        # set flags
        c = 0
        if self.data['op2'] in [0x1, 0x4, 0x5]:  # 32-bit
            v = overflow(result)
            av = advanced_overflow(result)
        elif self.data['op2'] in [0x2, 0x3, 0x6, 0x7]:  # 64-bit
            v = overflow_64(result).cast_to(Type.int_32)
            av = advanced_overflow_64(result).cast_to(Type.int_32)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")
