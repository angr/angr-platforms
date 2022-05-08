#!/usr/bin/env python3
""" rc_instr.py
Implementation of RC format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this, log_val


class RC_Instructions_8B(Instruction):
    """ A class for instructions with OP=8B """
    name = 'RC_Instructions_8B ...'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0xb)[2:].zfill(4))
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
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin.zfill(12)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:11]))
        op2 = int(op2.bin, 2)
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "RC_ADD"
        elif op2 == 0x2:
            self.name = "RC_ADDS"
        elif op2 == 0x3:
            self.name = "RC_ADDS.U"
        elif op2 == 0x4:
            self.name = "RC_ADDX"
        elif op2 == 0x5:
            self.name = "RC_ADDC"
        elif op2 == 0x8:
            self.name = "RC_RSUB"
        elif op2 == 0xa:
            self.name = "RC_RSUBS"
        elif op2 == 0xb:
            self.name = "RC_RSUBS.U"
        elif op2 == 0xe:
            self.name = "RC_ABSDIF"
        elif op2 == 0xf:
            self.name = "RC_ABSDIFS"
        elif op2 == 0x20:
            self.name = "RC_AND.EQ"
        elif op2 == 0x24:
            self.name = "RC_AND.GE"
        elif op2 == 0x25:
            self.name = "RC_AND.GE.U"
        elif op2 == 0x22:
            self.name = "RC_AND.LT"
        elif op2 == 0x23:
            self.name = "RC_AND.LT.U"
        elif op2 == 0x21:
            self.name = "RC_AND.NE"
        elif op2 == 0x10:
            self.name = "RC_EQ"
        elif op2 == 0x11:
            self.name = "RC_NE"
        elif op2 == 0x12:
            self.name = "RC_LT"
        elif op2 == 0x13:
            self.name = "RC_LT.U"
        elif op2 == 0x14:
            self.name = "RC_GE"
        elif op2 == 0x15:
            self.name = "RC_GE_U"
        elif op2 == 0x18:
            self.name = "RC_MIN"
        elif op2 == 0x19:
            self.name = "RC_MIN.U"
        elif op2 == 0x1A:
            self.name = "RC_MAX"
        elif op2 == 0x1B:
            self.name = "RC_MAX.U"
        elif op2 == 0x27:
            self.name = "RC_OR.EQ"
        elif op2 == 0x2B:
            self.name = "RC_OR.GE"
        elif op2 == 0x2C:
            self.name = "RC_OR.GE.U"
        elif op2 == 0x29:
            self.name = "RC_OR.LT"
        elif op2 == 0x2A:
            self.name = "RC_OR.LT.U"
        elif op2 == 0x28:
            self.name = "RC_OR.NE"
        elif op2 == 0x2F:
            self.name = "RC_XOR.EQ"
        elif op2 == 0x33:
            self.name = "RC_XOR.GE"
        elif op2 == 0x34:
            self.name = "RC_XOR.GE.U"
        elif op2 == 0x31:
            self.name = "RC_XOR.LT"
        elif op2 == 0x32:
            self.name = "RC_XOR.LT.U"
        elif op2 == 0x30:
            self.name = "RC_XOR.NE"
        elif op2 == 0x37:
            self.name = "RC_SH.EQ"
        elif op2 == 0x3B:
            self.name = "RC_SH.GE"
        elif op2 == 0x3C:
            self.name = "RC_SH.GE.U"
        elif op2 == 0x39:
            self.name = "RC_SH.LT"
        elif op2 == 0x3A:
            self.name = "RC_SH.LT.U"
        elif op2 == 0x38:
            self.name = "RC_SH.NE"
        elif op2 == 0x56:
            self.name = "RC_EQANY.B"
        elif op2 == 0x76:
            self.name = "RC_EQANY.H"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "const9": int(const9.hex, 16),
                "op2": op2,
                "c": int(c.hex, 16)}

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
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32)

    def get_const9_sign_extended(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const9(), self.get_const9_sign_extended()

    def compute_result(self, *args):
        d_a = args[0]
        const9 = args[1]
        const9_sign_extended = args[2]
        result = ""
        if self.data['op2'] == 0x0:  # ADD
            result = d_a + const9_sign_extended

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x2:  # ADDS
            result = ssov(d_a + const9_sign_extended, 32)

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x3:  # ADDS.U
            result = suov(d_a + const9_sign_extended, 32)

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x4:  # ADDX
            result = d_a + const9_sign_extended

            # compute flags
            c = carry(d_a, const9_sign_extended, 0)
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x5:  # ADDC
            psw = self.get_psw()
            result = d_a + const9_sign_extended + psw[31]

            # set flags
            c = carry(d_a, const9_sign_extended, psw[31])
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x8:  # RSUB
            result = const9_sign_extended - d_a

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0xa:  # RSUBS
            result = ssov32(const9_sign_extended - d_a, self.max_pos, self.max_neg)

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0xb:  # RSUBS.U
            result = suov32_sub(const9_sign_extended - d_a)  # Unsigned

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0xe:  # ABSDIF
            condition = extend_to_32_bits(d_a > const9_sign_extended)
            result = ((d_a - const9_sign_extended) & condition) | ((const9_sign_extended - d_a) & ~condition)

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0xf:  # ABSDIFS
            condition = extend_to_32_bits(d_a > const9_sign_extended)
            result = ((d_a - const9_sign_extended) & condition) | ((const9_sign_extended - d_a) & ~condition)

            # set flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x20:  # RC_AND.EQ
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a == const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x24:  # RC_AND.GE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a >= const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x25:  # RC_AND.GE.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a >= const9)  # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x22:  # RC_AND.LT
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a < const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x23:  # RC_AND.LT.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a < const9)  # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x21:  # RC_AND.NE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] & (d_a != const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x10:  # RC_EQ
            result = (d_a == const9_sign_extended)

        elif self.data['op2'] == 0x11:  # RC_NE
            result = (d_a != const9_sign_extended)

        elif self.data['op2'] == 0x12:  # RC_LT
            result = (d_a < const9_sign_extended)

        elif self.data['op2'] == 0x13:  # RC_LT.U
            result = (d_a < const9_sign_extended)  # Unsigned

        elif self.data['op2'] == 0x14:  # RC_GE
            result = (d_a >= const9_sign_extended)

        elif self.data['op2'] == 0x15:  # RC_GE_U
            result = (d_a >= const9)    # Unsigned

        elif self.data['op2'] == 0x18:  # RC_MIN
            condition = extend_to_32_bits(d_a < const9_sign_extended)
            result = (d_a & condition) | (const9_sign_extended & ~condition)

        elif self.data['op2'] == 0x19:  # RC_MIN.U
            condition = extend_to_32_bits(d_a < const9)  # Unsigned
            result = (d_a & condition) | (const9 & ~condition)

        elif self.data['op2'] == 0x1a:  # RC_MAX
            condition = extend_to_32_bits(d_a > const9_sign_extended)
            result = (d_a & condition) | (const9_sign_extended & ~condition)

        elif self.data['op2'] == 0x1b:  # RC_MAX.U
            condition = extend_to_32_bits(d_a > const9)  # Unsigned
            result = (d_a & condition) | (const9 & ~condition)

        elif self.data['op2'] == 0x27:  # RC_OR.EQ
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a == const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x2b:  # RC_OR.GE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a >= const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x2c:  # RC_OR.GE.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a >= const9)  # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x29:  # RC_OR.LT
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a < const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x2a:  # RC_OR.LT.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a < const9)  # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x28:  # RC_OR.NE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] | (d_a != const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x2f:  # RC_XOR.EQ
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a == const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x33:  # RC_XOR.GE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a >= const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x34:  # RC_XOR.GE.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a >= const9)  # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x31:  # RC_XOR.LT
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a < const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x32:  # RC_XOR.LT.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a < const9)   # Unsigned
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x30:  # RC_XOR.NE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            bit = d_c[0] ^ (d_a != const9_sign_extended)
            result = ((d_c >> 1) << 1) | bit

        elif self.data['op2'] == 0x37:  # RC_SH.EQ
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a == const9_sign_extended)

        elif self.data['op2'] == 0x3b:  # RC_SH.GE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a >= const9_sign_extended)

        elif self.data['op2'] == 0x3c:  # RC_SH.GE.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a >= const9)  # Unsigned

        elif self.data['op2'] == 0x39:  # RC_SH.LT
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a < const9_sign_extended)

        elif self.data['op2'] == 0x3a:  # RC_SH.LT.U
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a < const9)  # Unsigned

        elif self.data['op2'] == 0x38:  # RC_SH.NE
            d_c = self.get("d{0}".format(self.data['c']), Type.int_32)
            result = (d_c << 1) | (d_a != const9_sign_extended)

        elif self.data['op2'] == 0x56:  # EQANY.B
            cond_1 = ((d_a & 0xff) == (const9_sign_extended & 0xff))
            cond_2 = ((d_a & (0xff <<  8)) == (const9_sign_extended & (0xff <<  8)))
            cond_3 = ((d_a & (0xff << 16)) == (const9_sign_extended & (0xff << 16)))
            cond_4 = ((d_a & (0xff << 24)) == (const9_sign_extended & (0xff << 24)))
            result = cond_4 or cond_3 or cond_2 or cond_1

        elif self.data['op2'] == 0x76:  # EQANY.H
            cond_1 = ((d_a & 0xffff) == (const9_sign_extended & 0xffff))
            cond_2 = ((d_a & (0xffff <<  16)) == (const9_sign_extended & (0xffff <<  16)))
            result = cond_2 or cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RC_Instructions_8F(Instruction):
    """ A class for instructions with OP=8F """
    name = 'RC_Instructions_8F ...'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0xf)[2:].zfill(4))
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
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin.zfill(12)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:11]))
        op2 = int(op2.bin, 2)
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "RC_SH"
        elif op2 == 0x1:
            self.name = "RC_SHA"
        elif op2 == 0x8:
            self.name = "RC_AND"
        elif op2 == 0x9:
            self.name = "RC_NAND"
        elif op2 == 0xb:
            self.name = "RC_NOR"
        elif op2 == 0xa:
            self.name = "RC_OR"
        elif op2 == 0xf:
            self.name = "RC_ORN"
        elif op2 == 0xc:
            self.name = "RC_XOR"
        elif op2 == 0xe:
            self.name = "RC_ANDN"
        elif op2 == 0x40:
            self.name = "RC_SH.H"
        elif op2 == 0x41:
            self.name = "RC_SHA.H"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "const9": int(const9.hex, 16),
                "op2": op2,
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const9(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const9()

    def compute_result(self, *args):
        d_a = args[0]
        const9 = args[1]
        result = ""
        if self.data['op2'] == 0x0:  # Shift
            sha = self.data['const9'] & 0x3f  # const9[5:0]
            cond_sha_pos = (sha & 0x20 == 0)  # SHA is positive
            result_1 = (d_a << sha) & extend_to_32_bits(cond_sha_pos)
            result_2 = 0
            if not sha == 0:  # sha=0
                cond_sha_neg = extend_to_6_bits(cond_sha_pos) ^ 0x3f
                shift_count = twos_comp(sha, 6)    # if sha<0
                if shift_count < 0:
                    shift_count = shift_count * (-1)
                cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
                mask_2 = (((1 << shift_count) - 1) << (32 - shift_count)) & cond_mask_2
                result_2 = (mask_2 | (d_a >> shift_count)) & extend_to_32_bits(cond_sha_neg)
            # final result & flags
            result = result_1 | result_2

        elif self.data['op2'] == 0x1:  # SHA
            sha = self.data['const9'] & 0x3f  # const9[5:0]
            cond_sha_pos = (sha & 0x20 == 0)  # SHA is positive
            result_1 = (d_a << sha) & extend_to_32_bits(cond_sha_pos)
            # compute carry out
            lower_limit = (32 - sha) & extend_to_6_bits(cond_sha_pos)
            if lower_limit == 32:  # sha=0
                carry_out_1_mask = 0
            else:
                carry_out_1_mask = (((1 << 32) - 1) >> (31 - lower_limit)) << (31 - lower_limit)
            cond_carry_out_1 = ((sha & 0x3f) == 0x3f) & cond_sha_pos  # if const9[5:0]
            carry_out_1 = ((d_a & carry_out_1_mask) != 0) & extend_to_32_bits(cond_carry_out_1)

            result_2 = 0
            carry_out_2 = 0
            if not sha == 0:  # sha=0
                cond_sha_neg = extend_to_6_bits(cond_sha_pos) ^ 0x3f
                shift_count = twos_comp(sha, 6)    # if sha<0
                if shift_count < 0:
                    shift_count = shift_count * (-1)
                cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
                mask_2 = (((1 << shift_count) - 1) << (32 - shift_count)) & cond_mask_2
                result_2 = (mask_2 | (d_a >> shift_count)) & extend_to_32_bits(cond_sha_neg)
                # compute carry out
                carry_out_2_mask = (1 << (shift_count-1)) - 1
                carry_out_2 = ((d_a & carry_out_2_mask) != 0) & (cond_sha_pos ^ 1)

            # final result & flags
            result = result_1 | result_2
            c = carry_out_1 | carry_out_2
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x2:  # SHAS
            sha = self.data['const9'] & 0x3f  # const9[5:0]
            cond_sha_pos = (sha & 0x20 == 0)  # SHA is positive
            result_1 = (d_a << sha) & extend_to_32_bits(cond_sha_pos)
            # compute carry out
            lower_limit = (32 - sha) & extend_to_6_bits(cond_sha_pos)
            if lower_limit == 32:  # sha=0
                carry_out_1_mask = 0
            else:
                carry_out_1_mask = (((1 << 32) - 1) >> (31 - lower_limit)) << (31 - lower_limit)
            cond_carry_out_1 = ((sha & 0x3f) == 0x3f) & cond_sha_pos  # if const9[5:0]
            carry_out_1 = ((d_a & carry_out_1_mask) != 0) & extend_to_32_bits(cond_carry_out_1)

            result_2 = 0
            carry_out_2 = 0
            if not sha == 0:  # sha=0
                cond_sha_neg = extend_to_6_bits(cond_sha_pos) ^ 0x3f
                shift_count = twos_comp(sha, 6)    # if sha<0
                if shift_count < 0:
                    shift_count = shift_count * (-1)
                cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
                mask_2 = (((1 << shift_count) - 1) << (32 - shift_count)) & cond_mask_2
                result_2 = (mask_2 | (d_a >> shift_count)) & extend_to_32_bits(cond_sha_neg)
                # compute carry out
                carry_out_2_mask = (1 << (shift_count-1)) - 1
                carry_out_2 = ((d_a & carry_out_2_mask) != 0) & (cond_sha_pos ^ 1)

            # final result & flags
            result = ssov(result_1 | result_2, 32)
            c = carry_out_1 | carry_out_2
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x8:  # AND
            result = d_a & const9

        elif self.data['op2'] == 0x9:  # NAND
            result = ~(d_a & const9)

        elif self.data['op2'] == 0xb:  # NOR
            result = ~(d_a | const9)

        elif self.data['op2'] == 0xa:  # OR
            result = d_a | const9

        elif self.data['op2'] == 0xf:  # ORN
            result = d_a | (~const9)

        elif self.data['op2'] == 0xc:  # XOR
            result = d_a ^ const9

        elif self.data['op2'] == 0xe:  # ANDN
            result = d_a & ~const9

        elif self.data['op2'] == 0x40:  # SH.H
            sha = self.data['const9'] & 0x1f  # const9[4:0]
            cond_sha_pos = extend_to_16_bits(sha & 0x10 == 0)  # SHA is positive
            d_a_hw_1 = d_a >> 16       # 16 MSB bits [31:16]
            d_a_hw_2 = d_a & 0xffff    # 16 LSB bits [15:0]
            result_hw_1_pos = (d_a_hw_1 << sha) & cond_sha_pos
            result_hw_2_pos = (d_a_hw_2 << sha) & cond_sha_pos
            result_hw_1_neg = 0
            result_hw_2_neg = 0
            if not sha == 0:  # sha=0
                cond_sha_neg = cond_sha_pos ^ 0xffff
                shift_count = twos_comp(sha, 5)    # if sha<0
                if shift_count < 0:
                    shift_count = shift_count * (-1)  # TODO: get abs value
                cond_mask_hw_1_neg = extend_bits((d_a_hw_1 & 0x8000 != 0), shift_count)     # D[a][31] is set
                mask_2 = (((1 << shift_count) - 1) << (16 - shift_count)) & cond_mask_hw_1_neg
                result_hw_1_neg = (mask_2 | (d_a_hw_1 >> shift_count)) & cond_sha_neg

                cond_mask_hw_2_neg = extend_bits((d_a_hw_2 & 0x8000 != 0), shift_count)     # D[a][15] is set
                mask_2 = (((1 << shift_count) - 1) << (16 - shift_count)) & cond_mask_hw_2_neg
                result_hw_2_neg = (mask_2 | (d_a_hw_2 >> shift_count)) & cond_sha_neg

            # final result & flags
            result_hw_1 = result_hw_1_pos | result_hw_1_neg
            result_hw_2 = result_hw_2_pos | result_hw_2_neg
            result = (result_hw_1 << 16) | result_hw_2

        elif self.data['op2'] == 0x41:  # SHA.H
            sha = self.data['const9'] & 0x1f  # const9[4:0]
            cond_sha_pos = (sha & 0x10 == 0)  # SHA is positive
            result_hw_0_pos = ((d_a & 0xffff) << sha) & extend_to_16_bits(cond_sha_pos)
            result_hw_1_pos = ((d_a >> 16) << sha) & extend_to_16_bits(cond_sha_pos)

            result_hw_0_neg = 0
            result_hw_1_neg = 0
            if not sha == 0:  # sha=0
                cond_sha_neg = extend_to_16_bits(cond_sha_pos) ^ 0xffff
                shift_count = twos_comp(sha, 5)    # if sha<0
                if shift_count < 0:
                    shift_count = shift_count * (-1)
                cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
                mask_2 = (((1 << shift_count) - 1) << (16 - shift_count)) & cond_mask_2
                result_hw_0_neg = (mask_2 | ((d_a & 0xffff) >> shift_count)) & extend_to_16_bits(cond_sha_neg)
                result_hw_1_neg = (mask_2 | ((d_a >> 16) >> shift_count)) & extend_to_16_bits(cond_sha_neg)

            # final result
            result_1 = (result_hw_1_pos << 16) | result_hw_0_pos
            result_2 = (result_hw_1_neg << 16) | result_hw_0_neg
            result = result_1 | result_2

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RC_Instructions_53(Instruction):
    """ A class for instructions with OP=53 """
    name = 'RC_MUL_Instructions_53 ...'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(3)[2:].zfill(4))
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
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20].bin.zfill(12)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:11]))
        op2 = int(op2.bin, 2)
        c = tmp[:4]

        if op2 == 0x1:
            self.name = "RC_MUL (32-bit)"
        elif op2 == 0x2:
            self.name = "RC_MUL.U"
        elif op2 == 0x3:
            self.name = "RC_MUL (64-bit)"
        elif op2 == 0x4:
            self.name = "RC_MULS.U"
        elif op2 == 0x5:
            self.name = "RC_MULS"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "const9": int(const9.hex, 16),
                "op2": op2,
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT32_MAX_POS, Type.int_32).cast_to(Type.int_64, signed=True)

    @property
    def max_neg(self):
        return self.constant(INT32_MAX_NEG, Type.int_32).cast_to(Type.int_64, signed=True)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const9(self):
        return self.constant(self.data['const9'], Type.int_32)

    def get_const9_sign_extended(self):
        return self.constant(self.data['const9'], Type.int_9).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const9(), self.get_const9_sign_extended()

    def compute_result(self, *args):
        d_a = args[0]
        const9 = args[1]
        const9_sign_extended = args[2]
        result = ""
        if self.data['op2'] == 0x1:  # MUL (32-bit)
            result = d_a * const9_sign_extended
            self.put(result, self.get_dst_reg())

            # flags
            c = 0
            v = overflow(result)
            av = advanced_overflow(result)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x2:  # MUL.U
            result = d_a.cast_to(Type.int_64) * const9.cast_to(Type.int_64)  # Unsigned
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))
            self.put(result >> 32, "d{0}".format(self.data['c']+1))

            # flags
            c = 0
            v = overflow_64(result).cast_to(Type.int_32)
            av = advanced_overflow_64(result).cast_to(Type.int_32)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x3:  # MUL (64-bit)
            result = (d_a * const9_sign_extended).cast_to(Type.int_64, signed=True)
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))
            self.put(result >> 32, "d{0}".format(self.data['c']+1))

            # flags
            c = 0
            v = overflow_64(result).cast_to(Type.int_32)
            av = advanced_overflow_64(result).cast_to(Type.int_32)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x5:  # MULS
            result = (d_a * const9_sign_extended).cast_to(Type.int_64)
            result = ssov32(result, self.max_pos, self.max_neg)
            self.put(result, self.get_dst_reg())

            # flags
            c = 0
            v = overflow(result).cast_to(Type.int_32)
            av = advanced_overflow(result).cast_to(Type.int_32)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        elif self.data['op2'] == 0x4:  # MULS.U
            result = d_a * const9  # Unsigned
            result = suov32_pos(result)
            self.put(result, self.get_dst_reg())

            # set flags
            c = 0
            v = overflow(result).cast_to(Type.int_32)
            av = advanced_overflow(result).cast_to(Type.int_32)
            psw = self.get_psw()
            cond_sv = (v == 0)
            cond_sav = (av == 0)
            sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
            sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
            psw = set_usb(psw, c, v, sv, av, sav)
            self.put(psw, "psw")

        else:
            print("Error: Unknown OP2={0}!".format(self.data['op2']))
            print("RC instruction OP=53, OP2=Unknown")
            sys.exit(1)

class RC_Instructions_AD(Instruction):
    """ A class for instructions with OP=AD """
    name = 'RC Instructions (OP=0xAD) ...'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const9 = bitstring.BitArray(bin="{0}".format(tmp[11:20]))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:11]))
        op2 = int(op2.bin, 2)

        if op2 == 0x4:
            self.name = "RC_SYSCALL"
        else:
            self.name = "UNKNOWN"

        data = {"const9": int(const9.hex, 16),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_const9(self):
        return self.constant(self.data['const9'], Type.int_8)  # const9[7:0]

    def fetch_operands(self):
        return [self.get_const9()]

    def compute_result(self, *args):
        const9 = args[0]
        if self.data['op2'] == 0x4:  # SYSCALL
            # trap(SYS, const9[7:0]) TODO
            log_val("RC_Instructions_AD: trap(SYS, const9) - const9={0}".format(const9))

        else:
            print("Error: Unknown OP2={0}!".format(self.data['op2']))
            print("RC instruction OP=AD, OP2=Unknown")
            sys.exit(1)
