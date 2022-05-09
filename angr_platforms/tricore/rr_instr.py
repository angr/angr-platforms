#!/usr/bin/env python3
""" rr_instr.py
Implementation of RR format instructions.
"""
from pyvex.lifting.util import Type, Instruction, JumpKind
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RR_ABS_Inst(Instruction):
    """ Absolute Value instruction.
        op = 0x0B
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        result = get_abs_val(d_b, 32)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABS_B_Inst(Instruction):
    """ Absolute Value Packed Byte instruction.
        op = 0x0B
        op2 = 0x5C
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABS.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        result_byte3 = get_abs_val(((d_b & (0xff << 24)) >> 24), 8) << 24
        result_byte2 = get_abs_val(((d_b & (0xff << 16)) >> 16), 8) << 16
        result_byte1 = get_abs_val(((d_b & (0xff << 8)) >> 8), 8)   << 8
        result_byte0 = get_abs_val((d_b & 0xff), 8)
        result = result_byte3 | result_byte2 | result_byte1 | result_byte0

        # set flags
        c = 0
        ov_byte3 = (result_byte3 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte2 = (result_byte2 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte1 = (result_byte1 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte0 = (result_byte0 >> 7 != 0)  # result > 0x7F or result < -0x80
        v = ((ov_byte3 | ov_byte2 | ov_byte1 | ov_byte0) != 0)

        aov_byte3 = result_byte3[7]^result_byte3[6]
        aov_byte2 = result_byte2[7]^result_byte2[6]
        aov_byte1 = result_byte1[7]^result_byte1[6]
        aov_byte0 = result_byte0[7]^result_byte0[6]
        av = ((aov_byte3 | aov_byte2 | aov_byte1 | aov_byte0) != 0)

        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABS_H_Inst(Instruction):
    """ Absolute Value Packed Half-word instruction.
        op = 0x0B
        op2 = 0x7C
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        result_hw1 = get_abs_val(((d_b & (0xffff << 16)) >> 16), 16) << 16
        result_hw0 = get_abs_val((d_b & 0xffff), 16)
        result = result_hw1 | result_hw0

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSDIF_Inst(Instruction):
    """ Absolute Value of Difference instruction.
        op = 0x0B
        op2 = 0x0E
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSDIF'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = extend_to_32_bits(d_a > d_b)
        result = ((d_a - d_b) & condition) | ((d_b - d_a) & ~condition)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSDIF_B_Inst(Instruction):
    """ Absolute Value of Difference Packed Byte instruction.
        op = 0x0B
        op2 = 0x4E
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSDIF.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_byte3 = extend_to_8_bits(((d_a & (0xff << 24)) >> 24) > ((d_b & (0xff << 24)) >> 24))
        cond_byte2 = extend_to_8_bits(((d_a & (0xff << 16)) >> 16) > ((d_b & (0xff << 16)) >> 16))
        cond_byte1 = extend_to_8_bits(((d_a & (0xff << 8))  >> 8)  > ((d_b & (0xff << 8))  >> 8))
        cond_byte0 = extend_to_8_bits((d_a & 0xff) > (d_b & 0xff))

        result_byte3 = (((d_a & (0xff << 24)) >> 24) - ((d_b & (0xff << 24)) >> 24)) &  cond_byte3 | \
                       (((d_b & (0xff << 24)) >> 24) - ((d_a & (0xff << 24)) >> 24)) & (cond_byte3 ^ 0xff)

        result_byte2 = (((d_a & (0xff << 16)) >> 16) - ((d_b & (0xff << 16)) >> 16)) &  cond_byte2 | \
                       (((d_b & (0xff << 16)) >> 16) - ((d_a & (0xff << 16)) >> 16)) & (cond_byte2 ^ 0xff)

        result_byte1 = (((d_a & (0xff << 8)) >> 8)  - ((d_b & (0xff << 8)) >> 8)) &  cond_byte1 | \
                       (((d_b & (0xff << 8)) >> 8)  - ((d_a & (0xff << 8)) >> 8)) & (cond_byte1 ^ 0xff)

        result_byte0 = (((d_a & 0xff) - (d_b & 0xff)) &  cond_byte0) | \
                       (((d_b & 0xff) - (d_a & 0xff)) & (cond_byte0 ^ 0xff))

        result = (get_abs_val(result_byte3, 8) << 24) | \
                 (get_abs_val(result_byte2, 8) << 16) | \
                 (get_abs_val(result_byte1, 8) << 8) | \
                 get_abs_val(result_byte0, 8)

        # set flags
        c = 0
        ov_byte3 = (result_byte3 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte2 = (result_byte2 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte1 = (result_byte1 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte0 = (result_byte0 >> 7 != 0)  # result > 0x7F or result < -0x80
        v = ((ov_byte3 | ov_byte2 | ov_byte1 | ov_byte0) != 0)

        aov_byte3 = result_byte3[7]^result_byte3[6]
        aov_byte2 = result_byte2[7]^result_byte2[6]
        aov_byte1 = result_byte1[7]^result_byte1[6]
        aov_byte0 = result_byte0[7]^result_byte0[6]
        av = ((aov_byte3 | aov_byte2 | aov_byte1 | aov_byte0) != 0)

        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSDIF_H_Inst(Instruction):
    """ Absolute Value of Difference Packed Half-word instruction.
        op = 0x0B
        op2 = 0x6E
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSDIF.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_hw1 = extend_to_16_bits(((d_a & (0xffff << 16)) >> 16) > ((d_b & (0xffff << 16)) >> 16))
        cond_hw0 = extend_to_16_bits((d_a & 0xffff) > (d_b & 0xffff))

        result_hw1 = (((d_a & (0xffff << 16)) >> 16) - ((d_b & (0xffff << 16)) >> 16)) &  cond_hw1 | \
                     (((d_b & (0xffff << 16)) >> 16) - ((d_a & (0xffff << 16)) >> 16)) & (cond_hw1 ^ 0xffff)

        result_hw0 = (((d_a & 0xffff) - (d_b & 0xffff)) &  cond_hw0) | \
                     (((d_b & 0xffff) - (d_a & 0xffff)) & (cond_hw0 ^ 0xffff))

        result = (get_abs_val(result_hw1, 16) << 16) | get_abs_val(result_hw0, 16)

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSDIFS_Inst(Instruction):
    """ Absolute Value of Difference with Saturation instruction.
        op = 0x0B
        op2 = 0x0F
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSDIFS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = extend_to_32_bits(d_a > d_b)
        result = ssov(((d_a - d_b) & condition) | ((d_b - d_a) & ~condition), 32)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSDIFS_H_Inst(Instruction):
    """ Absolute Value of Difference Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x6F
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSDIFS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_hw1 = extend_to_16_bits(((d_a & (0xffff << 16)) >> 16) > ((d_b & (0xffff << 16)) >> 16))
        cond_hw0 = extend_to_16_bits((d_a & 0xffff) > (d_b & 0xffff))

        result_hw1 = (((d_a & (0xffff << 16)) >> 16) - ((d_b & (0xffff << 16)) >> 16)) &  cond_hw1 | \
                     (((d_b & (0xffff << 16)) >> 16) - ((d_a & (0xffff << 16)) >> 16)) & (cond_hw1 ^ 0xffff)

        result_hw0 = (((d_a & 0xffff) - (d_b & 0xffff)) &  cond_hw0) | \
                     (((d_b & 0xffff) - (d_a & 0xffff)) & (cond_hw0 ^ 0xffff))

        result = ssov((get_abs_val(result_hw1, 16) << 16), 16) | ssov(get_abs_val(result_hw0, 16), 16)

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSS_Inst(Instruction):
    """ Absolute Value with Saturation instruction.
        op = 0x0B
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        result = ssov(get_abs_val(d_b, 32), 32)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ABSS_H_Inst(Instruction):
    """ Absolute Value Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x7D
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR_ABSS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        result_hw1 = get_abs_val(((d_b & (0xffff << 16)) >> 16), 16)
        result_hw0 = get_abs_val((d_b & 0xffff), 16)
        result = (ssov(result_hw1, 16) << 16) | ssov(result_hw0, 16)

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result > 0x7FFF or result < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADD_Inst(Instruction):
    """ Add instruction.
        op = 0x0B
        op2 = 0x00
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADD'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + op2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a + d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

    def compute_flags(self, *args):
        retval = args[-1]
        v = (retval > 0x7FFFFFFF) or (retval < -80000000)
        av = retval[31] ^ retval[30]
        psw_val = self.get_psw()
        # set V & SV
        psw_val = (v).ite(
             psw_val | int("01100000000000000000000000000000", 2),
             psw_val & int("10111111111111111111111111111111", 2)
        )
        # set AV & SAV
        psw_val = (av).ite(
            psw_val | int("00011000000000000000000000000000", 2),
            psw_val & int("11101111111111111111111111111111", 2)
        )
        self.put(psw_val, "psw")

class RR_ADD_A_Inst(Instruction):
    """ Add Address instruction.
        op = 0x01
        op2 = 0x01
        User Status Flags: no change.
    """
    name = 'RR_ADD.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a + a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADD_B_Inst(Instruction):
    """ Add Packed Byte instruction.
        op = 0x0B
        op2 = 0x40
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADD.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_byte3 = (((d_a & (0xff << 24)) >> 24) + ((d_b & (0xff << 24)) >> 24)) & 0xff
        result_byte2 = (((d_a & (0xff << 16)) >> 16) + ((d_b & (0xff << 16)) >> 16)) & 0xff
        result_byte1 = (((d_a & (0xff << 8)) >> 8) + ((d_b & (0xff << 8)) >> 8)) & 0xff
        result_byte0 = ((((d_a & 0xff) + (d_b & 0xff)))) & 0xff

        result = (result_byte3 << 24) | (result_byte2 << 16) | (result_byte1 << 8) | result_byte0

        # set flags
        c = 0
        ov_byte3 = (result_byte3 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte2 = (result_byte2 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte1 = (result_byte1 >> 7 != 0)  # result > 0x7F or result < -0x80
        ov_byte0 = (result_byte0 >> 7 != 0)  # result > 0x7F or result < -0x80
        v = ((ov_byte3 | ov_byte2 | ov_byte1 | ov_byte0) != 0)

        aov_byte3 = result_byte3[7]^result_byte3[6]
        aov_byte2 = result_byte2[7]^result_byte2[6]
        aov_byte1 = result_byte1[7]^result_byte1[6]
        aov_byte0 = result_byte0[7]^result_byte0[6]
        av = ((aov_byte3 | aov_byte2 | aov_byte1 | aov_byte0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADD_H_Inst(Instruction):
    """ Add Packed Half-word instruction.
        op = 0x0B
        op2 = 0x60
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADD.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_hw1 = (((d_a & (0xffff << 16)) >> 16) + ((d_b & (0xffff << 16)) >> 16)) & 0xffff
        result_hw0 = ((((d_a & 0xffff) + (d_b & 0xffff)))) & 0xffff
        result = (result_hw1 << 16) | result_hw0

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result_hw1 > 0x7FFF or result_hw1 < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result_hw0 > 0x7FFF or result_hw0 < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDC_Inst(Instruction):
    """ Add with Carry instruction.
        op = 0x0B
        op2 = 0x05
        User Status Flags: C, V, SV, AV, SAV
    """
    name = 'RR_ADDC'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_psw()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        psw = args[2]
        return d_a + d_b + psw[31]

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

    def compute_flags(self, *args):
        retval = args[-1]
        psw_val = args[2]
        carry_out = carry(args[0], args[1], psw_val[31])  # d_a=args[0], d_b=args[1], psw[31]=args[2][31]

        # set psw.c = carry_out
        psw_val = (carry_out << 30) | (psw_val & 0x8fffffff)

        v = (retval > 0x7FFFFFFF) or (retval < -80000000)
        av = retval[31] ^ retval[30]
        # set V & SV
        psw_val = (v).ite(
             psw_val | int("01100000000000000000000000000000", 2),
             psw_val & int("10111111111111111111111111111111", 2)
        )
        # set AV & SAV
        psw_val = (av).ite(
            psw_val | int("00011000000000000000000000000000", 2),
            psw_val & int("11101111111111111111111111111111", 2)
        )
        self.put(psw_val, "psw")

class RR_ADDS_Inst(Instruction):
    """ Add Signed with Saturation instruction.
        op = 0x0B
        op2 = 0x02
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADDS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = ssov(d_a + d_b, 32)

        # set flags
        psw = self.get_psw()
        c = 0
        v = (result >> 32 != 0)
        sv = 0
        av = result[31] ^ result[30]
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDS_H_Inst(Instruction):
    """ Add Signed Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x62
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADDS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_hw1 = (((d_a & (0xffff << 16)) >> 16) + ((d_b & (0xffff << 16)) >> 16)) & 0xffff
        result_hw0 = ((d_a & 0xffff) + (d_b & 0xffff)) & 0xffff
        result = (ssov(result_hw1, 16) << 16) | ssov(result_hw0, 16)

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result_hw1 > 0x7FFF or result_hw1 < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result_hw0 > 0x7FFF or result_hw0 < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDS_HU_Inst(Instruction):
    """ Add Unsigned Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x63
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADDS.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_hw1 = (((d_a & (0xffff << 16)) >> 16) + ((d_b & (0xffff << 16)) >> 16))
        result_hw0 = ((d_a & 0xffff) + (d_b & 0xffff))
        result = (suov(result_hw1, 16) << 16) | suov(result_hw0, 16)

        # set flags
        c = 0
        ov_hw1 = (result_hw1 >> 15 != 0)  # result_hw1 > 0x7FFF or result_hw1 < -0x8000
        ov_hw0 = (result_hw0 >> 15 != 0)  # result_hw0 > 0x7FFF or result_hw0 < -0x8000
        v = ((ov_hw1 | ov_hw0) != 0)

        aov_hw1 = result_hw1[15]^result_hw1[14]
        aov_hw0 = result_hw0[15]^result_hw0[14]
        av = ((aov_hw1 | aov_hw0) != 0)

        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDS_U_Inst(Instruction):
    """ Add Unsigned with Saturation instruction.
        op = 0x0B
        op2 = 0x03
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_ADDS.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = suov(d_a + d_b, 32)

        # set flags
        psw = self.get_psw()
        c = 0
        v = (result >> 32 != 0)
        sv = v
        av = result[31] ^ result[30]
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDSC_A_Inst(Instruction):
    """ Add Scaled Index to Address instruction.
        op = 0x01
        op2 = 0x60
        User Status Flags: no change.
    """
    name = 'RR_ADDSC.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + 'n'*2 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        return a_b + (d_a << self.data['n'])

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDSC_AT_Inst(Instruction):
    """ Add Bit-Scaled Index to Address instruction.
        op = 0x01
        op2 = 0x62
        User Status Flags: no change.
    """
    name = 'RR_ADDSC.AT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        return (a_b + (d_a >> 3)) & 0xfffffffc

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ADDX_Inst(Instruction):
    """ Add Extended instruction.
        op = 0x0B
        op2 = 0x04
        User Status Flags: C, V, SV, AV, SAV
    """
    name = 'RR_ADDX'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a + d_b

        # set flags
        psw = self.get_psw()
        c = carry(d_a, d_b, 0)
        v = (result >> 32 != 0)
        sv = 0
        av = result[31] ^ result[30]
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_Inst(Instruction):
    """ RR AND instruction.
        op = 0x0F
        op2 = 0x08
    """
    name = 'RR_AND'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a & d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_EQ_Inst(Instruction):
    """ Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x20
        User Status Flags: no change.
    """
    name = 'RR_AND.EQ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + op2_1 + 'i'*4 + 'c'*4 + op2_2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a == d_b)         # D[c][0] AND D[a] == D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_GE_Inst(Instruction):
    """ Greater Than or Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x24
        User Status Flags: no change.
    """
    name = 'RR_AND.GE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a >= d_b)         # D[c][0] AND D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_GE_U_Inst(Instruction):
    """ Greater Than or Equal Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x25
        User Status Flags: no change.
    """
    name = 'RR_AND.GE.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a >= d_b)         # D[c][0] AND D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_LT_Inst(Instruction):
    """ Less Than Accumulating instruction.
        op = 0x0B
        op2 = 0x22
        User Status Flags: no change.
    """
    name = 'RR_AND.LT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a < d_b)          # D[c][0] AND D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_LT_U_Inst(Instruction):
    """ Less Than Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x23
        User Status Flags: no change.
    """
    name = 'RR_AND.LT.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a < d_b)          # D[c][0] AND D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_AND_NE_Inst(Instruction):
    """ Not Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x21
        User Status Flags: no change.
    """
    name = 'RR_AND.NE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] & (d_a != d_b)         # D[c][0] AND D[a] != D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ANDN_Inst(Instruction):
    """ Bitwise AND-Not instruction.
        op = 0x0F
        op2 = 0x0E
    """
    name = 'RR_ANDN'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a & ~d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_BMERGE_Inst(Instruction):
    """ Bit Merge instruction.
        op = 0x4B
        op2 = 0x01
    """
    name = 'RR_BMERGE'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c_31_24 = (((d_a >> 15) & 0x1) << 7) | \
                    (((d_b >> 15) & 0x1) << 6) | \
                    (((d_a >> 14) & 0x1) << 5) | \
                    (((d_b >> 14) & 0x1) << 4) | \
                    (((d_a >> 13) & 0x1) << 3) | \
                    (((d_b >> 13) & 0x1) << 2) | \
                    (((d_a >> 12) & 0x1) << 1) | \
                    ((d_b >> 12) & 0x1)
        d_c_23_16 = (((d_a >> 11) & 0x1) << 7) | \
                    (((d_b >> 11) & 0x1) << 6) | \
                    (((d_a >> 10) & 0x1) << 5) | \
                    (((d_b >> 10) & 0x1) << 4) | \
                    (((d_a >> 9) & 0x1) << 3) | \
                    (((d_b >> 9) & 0x1) << 2) | \
                    (((d_a >> 8) & 0x1) << 1) | \
                    ((d_b >> 8) & 0x1)
        d_c_15_8 =  (((d_a >> 7) & 0x1) << 7) | \
                    (((d_b >> 7) & 0x1) << 6) | \
                    (((d_a >> 6) & 0x1) << 5) | \
                    (((d_b >> 6) & 0x1) << 4) | \
                    (((d_a >> 5) & 0x1) << 3) | \
                    (((d_b >> 5) & 0x1) << 2) | \
                    (((d_a >> 4) & 0x1) << 1) | \
                    ((d_b >> 4) & 0x1)
        d_c_7_0 =   (((d_a >> 3) & 0x1) << 7) | \
                    (((d_b >> 3) & 0x1) << 6) | \
                    (((d_a >> 2) & 0x1) << 5) | \
                    (((d_b >> 2) & 0x1) << 4) | \
                    (((d_a >> 1) & 0x1) << 3) | \
                    (((d_b >> 1) & 0x1) << 2) | \
                    ((d_a & 0x1) << 1) | \
                    (d_b & 0x1)
        result = d_c_31_24 | d_c_23_16 | d_c_15_8 | d_c_7_0
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_BSPLIT_Inst(Instruction):
    """ Bit Split instruction.
        op = 0x4B
        op2 = 0x09
    """
    name = 'RR_BSPLIT'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        e_c_63_48 = 0
        e_c_47_40 = (((d_a >> 31) & 0x1) << 7) | \
                    (((d_a >> 29) & 0x1) << 6) | \
                    (((d_a >> 27) & 0x1) << 5) | \
                    (((d_a >> 25) & 0x1) << 4) | \
                    (((d_a >> 23) & 0x1) << 3) | \
                    (((d_a >> 21) & 0x1) << 2) | \
                    (((d_a >> 19) & 0x1) << 1) | \
                    ((d_a >> 17) & 0x1)
        e_c_39_32 = (((d_a >> 15) & 0x1) << 7) | \
                    (((d_b >> 13) & 0x1) << 6) | \
                    (((d_a >> 11) & 0x1) << 5) | \
                    (((d_b >> 9) & 0x1) << 4) | \
                    (((d_a >> 7) & 0x1) << 3) | \
                    (((d_b >> 5) & 0x1) << 2) | \
                    (((d_a >> 3) & 0x1) << 1) | \
                    ((d_b >> 1) & 0x1)
        e_c_31_16 = 0
        e_c_15_8  = (((d_a >> 30) & 0x1) << 7) | \
                    (((d_b >> 28) & 0x1) << 6) | \
                    (((d_a >> 26) & 0x1) << 5) | \
                    (((d_b >> 24) & 0x1) << 4) | \
                    (((d_a >> 22) & 0x1) << 3) | \
                    (((d_b >> 20) & 0x1) << 2) | \
                    (((d_a >> 18) & 0x1) << 1) | \
                    ((d_a >> 16) & 0x1)
        e_c_7_0  =  (((d_a >> 14) & 0x1) << 7) | \
                    (((d_b >> 12) & 0x1) << 6) | \
                    (((d_a >> 10) & 0x1) << 5) | \
                    (((d_b >> 8) & 0x1) << 4) | \
                    (((d_a >> 6) & 0x1) << 3) | \
                    (((d_b >> 4) & 0x1) << 2) | \
                    (((d_a >> 2) & 0x1) << 1) | \
                    (d_a & 0x1)
        self.put(e_c_63_48 | e_c_47_40 | e_c_39_32, "d{0}".format(self.data['c']+1))
        self.put(e_c_31_16 | e_c_15_8 | e_c_7_0, "d{0}".format(self.data['c']))

class RR_CALLI_Inst(Instruction):
    """ Call Indirect instruction.
        op = 0x2D
        op2 = 0x00
    """
    name = 'RR_CALLI'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + op2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2)}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return self.get_pc(), self.get_a_a()

    def compute_result(self, *args):
        pc = args[0]
        a_a = args[1]
        MASK_FCX_FCXS = 0x000f0000
        MASK_FCX_FCXO = 0x0000ffff
        fcx = self.get("fcx", Type.int_32)
        ea = ((fcx & MASK_FCX_FCXS) << 12) + ((fcx & MASK_FCX_FCXO) << 6)
        new_fcx = self.load(ea, Type.int_32)

        # save context upper
        pcxi = self.get("pcxi", Type.int_32)
        self.store(pcxi, ea)
        psw = self.get("psw", Type.int_32)
        self.store(psw, ea+4)
        a10 = self.get("a10", Type.int_32)
        self.store(a10, ea+8)
        a11 = self.get("a11", Type.int_32)
        self.store(a11, ea+12)
        d8 = self.get("d8", Type.int_32)
        self.store(d8, ea+16)
        d9 = self.get("d9", Type.int_32)
        self.store(d9, ea+20)
        d10 = self.get("d10", Type.int_32)
        self.store(d10, ea+24)
        d11 = self.get("d11", Type.int_32)
        self.store(d11, ea+28)
        a12 = self.get("a12", Type.int_32)
        self.store(a12, ea+32)
        a13 = self.get("a13", Type.int_32)
        self.store(a13, ea+36)
        a14 = self.get("a14", Type.int_32)
        self.store(a14, ea+40)
        a15 = self.get("a15", Type.int_32)
        self.store(a15, ea+44)
        d12 = self.get("d12", Type.int_32)
        self.store(d12, ea+48)
        d13 = self.get("d13", Type.int_32)
        self.store(d13, ea+52)
        d14 = self.get("d14", Type.int_32)
        self.store(d14, ea+56)
        d15 = self.get("d15", Type.int_32)
        self.store(d15, ea+60)

        # PCXI[19:0] = FCX[19:0]
        pcxi = (pcxi >> 20) << 20 | (fcx & 0xfffff)
        self.put(pcxi, "pcxi")

        # FCX[19:0] = new_FCX[19:0]
        fcx = (fcx >> 20) << 20 | (new_fcx & 0xfffff)
        self.put(fcx, "fcx")

        ret_addr = pc + 4
        self.put(ret_addr, "a11")

        dest = (a_a >> 1) << 1
        self.jump(None, dest, jumpkind=JumpKind.Call)

class RR_CLO_Inst(Instruction):
    """ Count Leading Ones instruction.
        op = 0x0F
        op2 = 0x1C
    """
    name = 'RR_CLO'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        return clo32(d_a)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_CLO_H_Inst(Instruction):
    """ Count Leading Ones in Packed Half-words instruction.
        op = 0x0F
        op2 = 0x7D
    """
    name = 'RR_CLO.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        result_hw1 = ((d_a & (0xffff << 16)) >> 16)
        result_hw0 = (d_a & 0xffff)
        result = (clo16(result_hw1) << 16) | clo16(result_hw0)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_CLS_Inst(Instruction):
    """ Count Leading Signs instruction.
        op = 0x0F
        op2 = 0x1D
    """
    name = 'RR_CLS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        return cls(d_a, 31)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_CLS_H_Inst(Instruction):
    """ Count Leading Signs in Packed Half-words instruction.
        op = 0x0F
        op2 = 0x7E
    """
    name = 'RR_CLS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        result_hw1 = ((d_a & (0xffff << 16)) >> 16)
        result_hw0 = (d_a & 0xffff)
        result = (cls(result_hw1, 15) << 16) | cls(result_hw0, 15)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_CLZ_Inst(Instruction):
    """ Count Leading Zeros instruction.
        op = 0x0F
        op2 = 0x1B
    """
    name = 'RR_CLZ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        return clz32(d_a)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_CLZ_H_Inst(Instruction):
    """ Count Leading Zeros in Packed Half-words instruction.
        op = 0x0F
        op2 = 0x7C
    """
    name = 'RR_CLZ.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        result_hw1 = ((d_a & (0xffff << 16)) >> 16)
        result_hw0 = (d_a & 0xffff)
        result = (clz16(result_hw1) << 16) | clz16(result_hw0)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_DVINIT_Inst(Instruction):
    """ Divide-Initialization Word instruction.
        op = 0x4B
        op2 = 0x1A
        TODO: set flags
    """
    name = 'RR_DVINIT'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_a_extended(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32).cast_to(Type.int_64, signed=True)

    def fetch_operands(self):
        return [self.get_d_a_extended()]

    def compute_result(self, *args):
        d_a_extended = args[0]
        # E[c] = D[c+1] | D[c]
        self.put(d_a_extended & 0xffffffff, "d{0}".format(self.data['c']))
        self.put(d_a_extended >> 32, "d{0}".format(self.data['c']+1))

class RR_DVINIT_B_Inst(Instruction):
    """ Divide-Initialization Byte instruction.
        op = 0x4B
        op2 = 0x5A
        User Status Flags: V, SV, AV
    """
    name = 'RR_DVINIT.B'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        quotient_sign = (d_a[31] != d_b[31])
        abs_sig_dividend = get_abs_val(d_a, 32) >> 7
        abs_base_dividend = get_abs_val(d_a, 32) & 0x7f
        abs_divisor = get_abs_val(d_b, 32)

        # E[c] = D[c+1] | D[c]
        result_1_1 = 0xffffff & extend_to_32_bits(quotient_sign)  # E[c][23:0]
        d_a_sign_extended = sign_extend_2(d_a, 32)
        result_1_2 = (d_a_sign_extended & 0xff) << 24             # E[c][31:24]
        result_1 = result_1_2 | result_1_1
        result_2 = sign_extend_2((d_a_sign_extended >> 8), 24)    # E[c][63:32] - The first 8 bits put to E[c][31:24]
        result_2 = result_2 | (extend_to_8_bits(d_a_sign_extended[31]) << 24)     # Move first 8-bits out and then
                                                                  # get a 8-bit value from MSB bit (bit 32)
                                                                  # then Add it to 8-bit MSB of result_2
                                                                  # to make it a 32-bit value (24+8=32).

        self.put(result_1, "d{0}".format(self.data['c']))
        self.put(result_2, "d{0}".format(self.data['c']+1))

        # set flags: V_1.3.0
        c = 0
        cond_overflow = (quotient_sign & (abs_divisor != 0))  # quotient_sign AND abs_divisor
        v = (((abs_sig_dividend == abs_divisor) &
              (abs_base_dividend >= abs_divisor)) | \
              (abs_sig_dividend > abs_divisor)) & cond_overflow
        v |= (abs_sig_dividend >= abs_divisor) & (cond_overflow^1)  # ELSE
        av = 0
        psw = self.get_psw()
        sv = v
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RR_DVINIT_BU_Inst(Instruction):
    """ Divide-Initialization Byte Unsigned instruction.
        op = 0x4B
        op2 = 0x4A
        User Status Flags: V, SV, AV
    """
    name = 'RR_DVINIT.BU'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        # E[c] = D[c+1] | D[c]
        result_1 = d_a << 24
        self.put(result_1, "d{0}".format(self.data['c']))
        result_2 = d_a >> 8
        self.put(result_2, "d{0}".format(self.data['c']+1))

        # set flags: V_1.3.0
        c = 0
        E_c_2 = self.get("d{0}".format(self.data['c']+1), Type.int_32)
        cond_overflow = (E_c_2 >= get_abs_val(d_b, 32))  # abs(E[c][63:32] >= abs(d_b))
        v =  1 & cond_overflow
        av = 0
        psw = self.get_psw()
        sv = v
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RR_DVINIT_H_Inst(Instruction):
    """ Divide-Initialization Half-word instruction.
        op = 0x4B
        op2 = 0x3A
        User Status Flags: V, SV, AV
    """
    name = 'RR_DVINIT.H'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        quotient_sign = (d_a[31] != d_b[31])
        abs_sig_dividend = get_abs_val(d_a, 32) >> 15
        abs_base_dividend = get_abs_val(d_a, 32) & 0x7fff
        abs_divisor = get_abs_val(d_b, 32)

        # E[c] = D[c+1] | D[c]
        result_1_1 = 0xffff & extend_to_32_bits(quotient_sign)  # E[c][15:0]
        d_a_sign_extended = sign_extend_2(d_a, 32)
        result_1_2 = (d_a_sign_extended & 0xffff) << 16             # E[c][31:16]
        result_1 = result_1_2 | result_1_1
        result_2 = sign_extend_2((d_a_sign_extended >> 16), 16)    # E[c][63:32] - The first 16 bits put to E[c][31:16]
        result_2 = result_2 | (extend_to_16_bits(d_a_sign_extended[31]) << 16)     # Move first 16-bits out and then
                                                                  # get a 16-bit value from MSB bit (bit 32)
                                                                  # then Add it to 16-bit MSB of result_2
                                                                  # to make it a 32-bit value (16+16=32).

        self.put(result_1, "d{0}".format(self.data['c']))
        self.put(result_2, "d{0}".format(self.data['c']+1))

        # set flags: V_1.3.0
        c = 0
        cond_overflow = (quotient_sign & (abs_divisor != 0))  # quotient_sign AND abs_divisor
        v = (((abs_sig_dividend == abs_divisor) &
              (abs_base_dividend >= abs_divisor)) | \
              (abs_sig_dividend > abs_divisor)) & cond_overflow
        v |= (abs_sig_dividend >= abs_divisor) & (cond_overflow^1)  # ELSE
        av = 0
        psw = self.get_psw()
        sv = v
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RR_DVINIT_HU_Inst(Instruction):
    """ Divide-Initialization Half-word Unsigned instruction.
        op = 0x4B
        op2 = 0x2A
        User Status Flags: V, SV, AV.
    """
    name = 'RR_DVINIT.HU'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        # E[c] = D[c+1] | D[c]
        result_1 = d_a << 16
        result_2 = d_a >> 16
        self.put(result_1, "d{0}".format(self.data['c']))
        self.put(result_2, "d{0}".format(self.data['c']+1))

        # set flags: V_1.3.0
        c = 0
        e_c_2 = get_abs_val(self.get("d{0}".format(self.data['c']+1), Type.int_32), 32)
        cond_overflow = (e_c_2 >= get_abs_val(d_b, 32))  # abs(E[c][63:32] >= abs(d_b))
        v =  1 & cond_overflow
        av = 0
        psw = self.get_psw()
        sv = v
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RR_DVINIT_U_Inst(Instruction):
    """ Divide-Initialization Word Unsigned instruction.
        op = 0x4B
        op2 = 0x0A
        TODO: set flags
    """
    name = 'RR_DVINIT.U'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*2 + '00' + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        # E[c] = D[c+1] | D[c]
        self.put(d_a, "d{0}".format(self.data['c']))
        zero = self.constant(0, Type.int_32)
        self.put(zero, "d{0}".format(self.data['c']+1))

class RR_EQ_Inst(Instruction):
    """ Equal instruction.
        op = 0x0B
        op2 = 0x10
    """
    name = 'RR_EQ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a == d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQ_A_Inst(Instruction):
    """ Equal to Address instruction.
        op = 0x01
        op2 = 0x40
    """
    name = 'RR_EQ.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a == a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQ_B_Inst(Instruction):
    """ Equal Packed Byte instruction.
        op = 0x0B
        op2 = 0x50
    """
    name = 'RR_EQ.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) == (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) == (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) == (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) == (d_b & (0xff << 24)))
        result = (0xff << 24) & (cond_4 << 24) | \
                 (0xff << 16) & (cond_3 << 16) | \
                 (0xff << 8)  & (cond_2 << 8)  | \
                 (0xff)       &  cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQ_H_Inst(Instruction):
    """ Equal Packed Half-word instruction.
        op = 0x0B
        op2 = 0x70
    """
    name = 'RR_EQ.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) == (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff << 16)) == (d_b & (0xffff << 16)))
        result = (0xffff << 16) & (cond_2 << 16) | \
                 (0xffff)       &  cond_1
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQ_W_Inst(Instruction):
    """ Equal Packed Word instruction.
        op = 0x0B
        op2 = 0x90
    """
    name = 'RR_EQ.W'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(9)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond = extend_to_32_bits(d_a == d_b)
        result = 0xffffffff & cond
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQANY_B_Inst(Instruction):
    """ Equal Any Byte instruction.
        op = 0x0B
        op2 = 0x56
    """
    name = 'RR_EQANY.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = ((d_a & 0xff) == (d_b & 0xff))
        cond_2 = ((d_a & (0xff <<  8)) == (d_b & (0xff <<  8)))
        cond_3 = ((d_a & (0xff << 16)) == (d_b & (0xff << 16)))
        cond_4 = ((d_a & (0xff << 24)) == (d_b & (0xff << 24)))
        result = cond_4 or cond_3 or cond_2 or cond_1
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQANY_H_Inst(Instruction):
    """ Equal Any Half-word instruction.
        op = 0x0B
        op2 = 0x76
    """
    name = 'RR_EQANY.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = ((d_a & 0xffff) == (d_b & 0xffff))
        cond_2 = ((d_a & (0xffff << 16)) == (d_b & (0xffff << 16)))
        result = cond_2 or cond_1
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_EQZ_A_Inst(Instruction):
    """ Equal Zero Address instruction.
        op = 0x01
        op2 = 0x48
    """
    name = 'RR_EQZ.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'j'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_a()]

    def compute_result(self, *args):
        a_a = args[0]
        return a_a == 0

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_GE_Inst(Instruction):
    """ Greater Than or Equal instruction.
        op = 0x0B
        op2 = 0x14
    """
    name = 'RR_GE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return (d_a.signed >= d_b).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_GE_U_Inst(Instruction):
    """ Greater Than or Equal Unsigned instruction.
        op = 0x0B
        op2 = 0x15
    """
    name = 'RR_GE.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a >= d_b  # Unsigned comparison

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_GE_A_Inst(Instruction):
    """ Greater Than or Equal Address instruction.
        op = 0x01
        op2 = 0x43
    """
    name = 'RR_GE.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a >= a_b  # Unsigned

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_JI_Inst(Instruction):
    """ Jump Indirect instruction.
        op = 0x2D
        op2 = 0x03
    """
    name = 'RR_JI'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2)}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_a()]

    def compute_result(self, *args):
        a_a = args[0]
        dest = (a_a >> 1) << 1
        self.jump(None, dest)

class RR_JLI_Inst(Instruction):
    """ Jump and Link Indirect instruction.
        op = 0x2D
        op2 = 0x02
    """
    name = 'RR_JLI'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2)}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_pc()

    def compute_result(self, *args):
        a_a = args[0]
        pc = args[1]
        ret_addr = pc + 4
        self.put(ret_addr, "a11")

        dest = (a_a >> 1) << 1
        self.jump(None, dest)

class RR_LT_Inst(Instruction):
    """ Less Than instruction.
        op = 0x0B
        op2 = 0x12
    """
    name = 'RR_LT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return (d_a.signed < d_b).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_U_Inst(Instruction):
    """ Less Than Unsigned instruction.
        op = 0x0B
        op2 = 0x13
    """
    name = 'RR_LT.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a < d_b  # unsigned comparison

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_A_Inst(Instruction):
    """ Less Than Address instruction.
        op = 0x01
        op2 = 0x42
    """
    name = 'RR_LT.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a < a_b  # Unsigned comparison

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_B_Inst(Instruction):
    """ Less Than Packed Byte instruction.
        op = 0x0B
        op2 = 0x52
    """
    name = 'RR_LT.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) < (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) < (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) < (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) < (d_b & (0xff << 24)))
        result = (0xff << 24) & (cond_4 << 24) | \
                 (0xff << 16) & (cond_3 << 16) | \
                 (0xff << 8)  & (cond_2 << 8)  | \
                 (0xff)       &  cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_BU_Inst(Instruction):
    """ Less Than Packed Byte Unsigned instruction.
        op = 0x0B
        op2 = 0x53
    """
    name = 'RR_LT.BU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) < (d_b & 0xff))  # Unsigned
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) < (d_b & (0xff <<  8)))  # Unsigned
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) < (d_b & (0xff << 16)))  # Unsigned
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) < (d_b & (0xff << 24)))  # Unsigned
        result = (0xff << 24) & (cond_4 << 24) | \
                 (0xff << 16) & (cond_3 << 16) | \
                 (0xff << 8)  & (cond_2 << 8)  | \
                 (0xff)       &  cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_H_Inst(Instruction):
    """ Less Than Packed Half-word instruction.
        op = 0x0B
        op2 = 0x72
    """
    name = 'RR_LT.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) < (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff << 16)) < (d_b & (0xffff << 16)))
        result = (0xffff << 16) & (cond_2 << 16) | \
                 (0xffff)       &  cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_HU_Inst(Instruction):
    """ Less Than Packed Half-word Unsigned instruction.
        op = 0x0B
        op2 = 0x73
    """
    name = 'RR_LT.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) < (d_b & 0xffff)) # Unsigned
        cond_2 = extend_to_16_bits((d_a & (0xffff << 16)) < (d_b & (0xffff << 16)))  # Unsigned
        result = (0xffff << 16) & (cond_2 << 16) | \
                 (0xffff)       &  cond_1

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_W_Inst(Instruction):
    """ Less Than Packed Word instruction.
        op = 0x0B
        op2 = 0x92
    """
    name = 'RR_LT.W'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(9)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond = extend_to_32_bits(d_a < d_b)
        result = 0xffffffff & cond
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_LT_WU_Inst(Instruction):
    """ Less Than Packed Word Unsigned instruction.
        op = 0x0B
        op2 = 0x93
    """
    name = 'RR_LT.WU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(9)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond = extend_to_32_bits(d_a < d_b)  # Unsigned
        result = 0xffffffff & cond
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_Inst(Instruction):
    """ Maximum Value instruction.
        op = 0x0B
        op2 = 0x1A
    """
    name = 'RR_MAX'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = extend_to_32_bits(d_a > d_b)
        result = (d_a & condition) | (d_b & ~condition)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_U_Inst(Instruction):
    """ Maximum Value Unsigned instruction.
        op = 0x0B
        op2 = 0x1B
    """
    name = 'RR_MAX.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = d_a > d_b
        return self.ite(condition, d_a, d_b)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_B_Inst(Instruction):
    """ Maximum Value Packed Byte instruction.
        op = 0x0B
        op2 = 0x5A
    """
    name = 'RR_MAX.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) > (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) > (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) > (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) > (d_b & (0xff << 24)))
        result = (d_a & 0xff000000 & (cond_4 << 24)) | (d_b & 0xff000000 & (~cond_4 << 24)) |\
                 (d_a & 0xff0000 & (cond_3 << 16)) | (d_b & 0xff0000 & (~cond_3 << 16)) |\
                 ((d_a & 0xff00 & (cond_2 << 8)) | (d_b & 0xff00 & (~cond_2 << 8))) |\
                 (d_a & 0xff & cond_1) | (d_b & 0xff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_BU_Inst(Instruction):
    """ Maximum Value Packed Byte Unsigned instruction.
        op = 0x0B
        op2 = 0x5B
    """
    name = 'RR_MAX.BU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) > (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) > (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) > (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) > (d_b & (0xff << 24)))
        result = (d_a & 0xff000000 & (cond_4 << 24)) | (d_b & 0xff000000 & (~cond_4 << 24)) |\
                 (d_a & 0xff0000 & (cond_3 << 16)) | (d_b & 0xff0000 & (~cond_3 << 16)) |\
                 ((d_a & 0xff00 & (cond_2 << 8)) | (d_b & 0xff00 & (~cond_2 << 8))) |\
                 (d_a & 0xff & cond_1) | (d_b & 0xff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_H_Inst(Instruction):
    """ Maximum Value Packed Half-word instruction.
        op = 0x0B
        op2 = 0x7A
    """
    name = 'RR_MAX.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) > (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff <<  16)) > (d_b & (0xffff <<  16)))
        result = ((d_a & 0xffff0000 & (cond_2 << 16)) | (d_b & 0xffff0000 & (~cond_2 << 16))) |\
                 (d_a & 0xffff & cond_1) | (d_b & 0xffff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MAX_HU_Inst(Instruction):
    """ Maximum Value Packed Half-word Unsigned instruction.
        op = 0x0B
        op2 = 0x7B
    """
    name = 'RR_MAX.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) > (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff <<  16)) > (d_b & (0xffff <<  16)))
        result = ((d_a & 0xffff0000 & (cond_2 << 16)) | (d_b & 0xffff0000 & (~cond_2 << 16))) |\
                 (d_a & 0xffff & cond_1) | (d_b & 0xffff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_Inst(Instruction):
    """ Minimum Value instruction.
        op = 0x0B
        op2 = 0x18
    """
    name = 'RR_MIN'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = extend_to_32_bits(d_a < d_b)
        result = (d_a & condition) | (d_b & ~condition)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_U_Inst(Instruction):
    """ Minimum Value Unsigned instruction.
        op = 0x0B
        op2 = 0x19
    """
    name = 'RR_MIN.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        condition = d_a < d_b
        return self.ite(condition, d_a, d_b)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_B_Inst(Instruction):
    """ Minimum Value Packed Byte instruction.
        op = 0x0B
        op2 = 0x58
    """
    name = 'RR_MIN.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) < (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) < (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) < (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) < (d_b & (0xff << 24)))
        result = (d_a & 0xff000000 & (cond_4 << 24)) | (d_b & 0xff000000 & (~cond_4 << 24)) |\
                 (d_a & 0xff0000 & (cond_3 << 16)) | (d_b & 0xff0000 & (~cond_3 << 16)) |\
                 ((d_a & 0xff00 & (cond_2 << 8)) | (d_b & 0xff00 & (~cond_2 << 8))) |\
                 (d_a & 0xff & cond_1) | (d_b & 0xff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_BU_Inst(Instruction):
    """ Minimum Value Packed Byte Unsigned instruction.
        op = 0x0B
        op2 = 0x59
    """
    name = 'RR_MIN.BU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(5)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_8_bits((d_a & 0xff) < (d_b & 0xff))
        cond_2 = extend_to_8_bits((d_a & (0xff <<  8)) < (d_b & (0xff <<  8)))
        cond_3 = extend_to_8_bits((d_a & (0xff << 16)) < (d_b & (0xff << 16)))
        cond_4 = extend_to_8_bits((d_a & (0xff << 24)) < (d_b & (0xff << 24)))
        result = (d_a & 0xff000000 & (cond_4 << 24)) | (d_b & 0xff000000 & (~cond_4 << 24)) |\
                 (d_a & 0xff0000 & (cond_3 << 16)) | (d_b & 0xff0000 & (~cond_3 << 16)) |\
                 ((d_a & 0xff00 & (cond_2 << 8)) | (d_b & 0xff00 & (~cond_2 << 8))) |\
                 (d_a & 0xff & cond_1) | (d_b & 0xff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_H_Inst(Instruction):
    """ Minimum Value Packed Half-word instruction.
        op = 0x0B
        op2 = 0x78
    """
    name = 'RR_MIN.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) < (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff <<  16)) < (d_b & (0xffff <<  16)))
        result = ((d_a & 0xffff0000 & (cond_2 << 16)) | (d_b & 0xffff0000 & (~cond_2 << 16))) |\
                 (d_a & 0xffff & cond_1) | (d_b & 0xffff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MIN_HU_Inst(Instruction):
    """ Minimum Value Packed Half-word Unsigned instruction.
        op = 0x0B
        op2 = 0x79
    """
    name = 'RR_MIN.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        cond_1 = extend_to_16_bits((d_a & 0xffff) < (d_b & 0xffff))
        cond_2 = extend_to_16_bits((d_a & (0xffff <<  16)) < (d_b & (0xffff <<  16)))
        result = ((d_a & 0xffff0000 & (cond_2 << 16)) | (d_b & 0xffff0000 & (~cond_2 << 16))) |\
                 (d_a & 0xffff & cond_1) | (d_b & 0xffff & ~cond_1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MOV_Inst(Instruction):
    """ Move Value to Address Register instruction.
        op = 0x0B
        op2 = 0x1F
        User Status Flags: no change.
    """
    name = 'RR_MOV'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'i'*4 + op2_2 + 'j'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        return d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MOV_A_Inst(Instruction):
    """ Move Value to Address Register instruction.
        op = 0x01
        op2 = 0x63
        User Status Flags: no change.
    """
    name = 'RR_MOV.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'i'*4 + op2_2 + 'j'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        return d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MOV_AA_Inst(Instruction):
    """ Move Address from Address Register instruction.
        op = 0x01
        op2 = 0x00
        User Status Flags: no change.
    """
    name = 'RR_MOV.AA'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'i'*4 + op2_2 + 'j'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_MOV_D_Inst(Instruction):
    """ Move Address to Data Register instruction.
        op = 0x01
        op2 = 0x4C
        User Status Flags: no change.
    """
    name = 'RR_MOV.D'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'i'*4 + op2_2 + 'j'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_NAND_Inst(Instruction):
    """ Bitwise NAND instruction.
        op = 0x0F
        op2 = 0x09
    """
    name = 'RR_NAND'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return ~(d_a & d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_NE_Inst(Instruction):
    """ Not Equal instruction.
        op = 0x0B
        op2 = 0x11
    """
    name = 'RR_NE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return (d_a != d_b).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_NE_A_Inst(Instruction):
    """ Not Equal Address instruction.
        op = 0x01
        op2 = 0x41
    """
    name = 'RR_NE.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return (a_a != a_b).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_NEZ_A_Inst(Instruction):
    """ Not Equal Zero Address instruction.
        op = 0x01
        op2 = 0x49
    """
    name = 'RR_NEZ.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_a()]

    def compute_result(self, *args):
        a_a = args[0]
        return a_a != 0

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_NOR_Inst(Instruction):
    """ RR NOR instruction.
        op = 0x0F
        op2 = 0x0B
    """
    name = 'RR_NOR'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        s1 = args[0]
        s2 = args[1]
        return ~(s1 | s2)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_Inst(Instruction):
    """ Bitwise OR instruction.
        op = 0x0F
        op2 = 0x0A
    """
    name = 'RR_OR'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a | d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_EQ_Inst(Instruction):
    """ Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x27
        User Status Flags: no change.
    """
    name = 'RR_OR.EQ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(7)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a == d_b)
        result = ((d_c >> 1) << 1) | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_GE_Inst(Instruction):
    """ OR Greater Than or Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x2B
        User Status Flags: no change.
    """
    name = 'RR_OR.GE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a >= d_b)         # D[c][0] OR D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_GE_U_Inst(Instruction):
    """ Greater Than or Equal Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x2C
        User Status Flags: no change.
    """
    name = 'RR_OR.GE.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a >= d_b)         # D[c][0] OR D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_LT_Inst(Instruction):
    """ OR Less Than Accumulating instruction.
        op = 0x0B
        op2 = 0x29
        User Status Flags: no change.
    """
    name = 'RR_OR.LT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a < d_b)           # D[c][0] OR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit     # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_LT_U_Inst(Instruction):
    """ Less Than Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x2A
        User Status Flags: no change.
    """
    name = 'RR_OR.LT.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a < d_b)          # D[c][0] OR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_OR_NE_Inst(Instruction):
    """ OR Not Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x28
        User Status Flags: no change.
    """
    name = 'RR_OR.NE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] | (d_a != d_b)         # D[c][0] OR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_ORN_Inst(Instruction):
    """ Bitwise OR-Not instruction.
        op = 0x0F
        op2 = 0x0F
    """
    name = 'RR_ORN'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a | ~d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_PARITY_Inst(Instruction):
    """ Parity instruction.
        op = 0x4B
        op2 = 0x02
    """
    name = 'RR_PARITY'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c_31_24 = (((d_a >> 31) & 0x1) ^ ((d_b >> 30) & 0x1) ^ \
                     ((d_a >> 29) & 0x1) ^ ((d_b >> 28) & 0x1) ^ \
                     ((d_a >> 27) & 0x1) ^ ((d_b >> 26) & 0x1) ^ \
                     ((d_a >> 25) & 0x1) ^ ((d_a >> 24) & 0x1))
        d_c_23_16 = (((d_a >> 23) & 0x1) ^ ((d_b >> 22) & 0x1) ^ \
                     ((d_a >> 21) & 0x1) ^ ((d_b >> 20) & 0x1) ^ \
                     ((d_a >> 19) & 0x1) ^ ((d_b >> 18) & 0x1) ^ \
                     ((d_a >> 17) & 0x1) ^ ((d_a >> 16) & 0x1))
        d_c_15_8  = (((d_a >> 15) & 0x1) ^ ((d_b >> 14) & 0x1) ^ \
                     ((d_a >> 13) & 0x1) ^ ((d_b >> 12) & 0x1) ^ \
                     ((d_a >> 11) & 0x1) ^ ((d_b >> 10) & 0x1) ^ \
                     ((d_a >> 9) & 0x1) ^ ((d_a >> 8) & 0x1))
        d_c_7_0   = (((d_a >> 7) & 0x1) ^ ((d_b >> 6) & 0x1) ^ \
                     ((d_a >> 5) & 0x1) ^ ((d_b >> 4) & 0x1) ^ \
                     ((d_a >> 3) & 0x1) ^ ((d_b >> 2) & 0x1) ^ \
                     ((d_a >> 1) & 0x1) ^ (d_a & 0x1))
        self.put((d_c_31_24<<24) | (d_c_23_16<<16) | (d_c_15_8<<8) | d_c_7_0, "d{0}".format(self.data['c']))

class RR_SAT_HU_Inst(Instruction):
    """ Saturate Half-word Unsigned instruction:
        op = 0x0B
        op2 = 0x7F
    """
    name = 'RR_SAT.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(7)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        pos_cond = extend_to_32_bits(d_a > 0xffff)
        result = (0xffff & pos_cond) | d_a & (pos_cond^0xffffffff)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_Inst(Instruction):
    """ Shift instruction.
        op = 0x0F
        op2 = 0x00
    """
    name = 'RR_SH'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        sha = d_b.cast_to(Type.int_6).cast_to(Type.int_32, signed=True)
        condition = sha.signed >= 0
        result = self.ite(condition,
                          d_a << sha.cast_to(Type.int_8),
                          d_a >> (sha.signed * (-1)).cast_to(Type.int_8))
        return result

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_EQ_Inst(Instruction):
    """ Shift Equal instruction.
        op = 0x0B
        op2 = 0x37
    """
    name = 'RR_SH.EQ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(7)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a == d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_GE_Inst(Instruction):
    """ Shift Greater Than or Equal instruction.
        op = 0x0B
        op2 = 0x3B
    """
    name = 'RR_SH.GE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a >= d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_GE_U_Inst(Instruction):
    """ Shift Greater Than or Equal Unsigned instruction.
        op = 0x0B
        op2 = 0x3C
    """
    name = 'RR_SH.GE.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a >= d_b)  # Unsigned

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_LT_Inst(Instruction):
    """ Shift Less Than instruction.
        op = 0x0B
        op2 = 0x39
    """
    name = 'RR_SH.LT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a < d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_LT_U_Inst(Instruction):
    """ Shift Less Than Unsigned instruction.
        op = 0x0B
        op2 = 0x3A
    """
    name = 'RR_SH.LT.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a < d_b)  # Unsigned

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_H_Inst(Instruction):
    """ Shift Packed Half-words instruction.
        op = 0x0F
        op2 = 0x40
    """
    name = 'RR_SH.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        sha = d_b & 0x1f  # D[b][4:0]
        cond_sha_pos = extend_to_16_bits(sha & 0x10 == 0)  # if SHA is positive

        # get Half-words
        d_a_hw_1 = d_a >> 16       # 16 MSB bits [31:16]
        d_a_hw_2 = d_a & 0xffff    # 16 LSB bits [15:0]

        # shift Half-words of SHA is positive
        result_hw_1_pos = (d_a_hw_1 << sha.cast_to(Type.int_8)) & cond_sha_pos
        result_hw_2_pos = (d_a_hw_2 << sha.cast_to(Type.int_8)) & cond_sha_pos

        # if SHA is negative
        cond_sha_neg = cond_sha_pos ^ 0xffff
        shift_count = twos_comp(sha, 5) & (cond_sha_neg != 0)    # if sha<0
        shift_count = get_abs_val(shift_count, 5)

        # shift Half-words if SHA is negative
        mask_2 = (((1 << shift_count.cast_to(Type.int_8)) - 1) << (16 - shift_count.cast_to(Type.int_8)))
        result_hw_1_neg = (mask_2.cast_to(Type.int_32) | (d_a_hw_1 >> shift_count.cast_to(Type.int_8))) & cond_sha_neg
        mask_2 = (((1 << shift_count.cast_to(Type.int_8)) - 1) << (16 - shift_count.cast_to(Type.int_8)))
        result_hw_2_neg = (mask_2.cast_to(Type.int_32) | (d_a_hw_2 >> shift_count.cast_to(Type.int_8))) & cond_sha_neg

        # final result
        result_hw_1 = result_hw_1_pos | result_hw_1_neg
        result_hw_2 = result_hw_2_pos | result_hw_2_neg
        result = (result_hw_1 << 16) | result_hw_2

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SH_NE_Inst(Instruction):
    """ Shift Not Equal instruction.
        op = 0x0B
        op2 = 0x38
    """
    name = 'RR_SH.NE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        return (d_c << 1) | (d_a != d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SHA_Inst(Instruction):
    """ Arithmetic Shift instruction.
        op = 0x0F
        op2 = 0x01
    """
    name = 'RR_SHA'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        sha = d_b.cast_to(Type.int_6).cast_to(Type.int_32, signed=True)
        cond_pos = extend_to_32_bits(sha.signed >= 0)
        cond_bit = extend_to_32_bits(d_a[31] == 1)
        sha2 = (sha.signed * (-1)).cast_to(Type.int_8)
        msk = (((1 << sha2) - 1) << (32 - sha2)).cast_to(Type.int_32) & cond_bit
        result = (d_a << sha.cast_to(Type.int_8)) & cond_pos | \
                 (msk | (d_a >> (sha.signed * (-1)).cast_to(Type.int_8))) & (~cond_pos)

        # set flags
        psw = self.get_psw()
        c = 0
        v = 0
        sv = 0
        av = 0
        sav = 0
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SHA_H_Inst(Instruction):
    """ Arithmetic Shift Packed Half-words instruction.
        op = 0x0F
        op2 = 0x41
    """
    name = 'RR_SHA.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        sha = d_b & 0x1f  # D[b][4:0]
        cond_sha_pos = extend_to_16_bits(sha & 0x10 == 0)  # if SHA is positive

        # get Half-words
        d_a_hw_1 = d_a >> 16       # 16 MSB bits [31:16]
        d_a_hw_2 = d_a & 0xffff    # 16 LSB bits [15:0]

        # shift Half-words of SHA is positive
        result_hw_1_pos = (d_a_hw_1 << sha.cast_to(Type.int_8)) & cond_sha_pos
        result_hw_2_pos = (d_a_hw_2 << sha.cast_to(Type.int_8)) & cond_sha_pos

        # if SHA is negative
        cond_sha_neg = cond_sha_pos ^ 0xffff
        shift_count = twos_comp(sha, 5) & (cond_sha_neg != 0)    # if sha<0
        shift_count = get_abs_val(shift_count, 5)

        # shift Half-words if SHA is negative
        mask_2 = (((1 << shift_count.cast_to(Type.int_8)) - 1) << (16 - shift_count.cast_to(Type.int_8)))
        result_hw_1_neg = (mask_2.cast_to(Type.int_32) | (d_a_hw_1 >> shift_count.cast_to(Type.int_8))) & cond_sha_neg
        mask_2 = (((1 << shift_count.cast_to(Type.int_8)) - 1) << (16 - shift_count.cast_to(Type.int_8)))
        result_hw_2_neg = (mask_2.cast_to(Type.int_32) | (d_a_hw_2 >> shift_count.cast_to(Type.int_8))) & cond_sha_neg

        # final result
        result_hw_1 = result_hw_1_pos | result_hw_1_neg
        result_hw_2 = result_hw_2_pos | result_hw_2_neg
        result = (result_hw_1 << 16) | result_hw_2

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SHAS_Inst(Instruction):
    """ Arithmetic Shift with Saturation instruction.
        op = 0x0F
        op2 = 0x02
    """
    name = 'RR_SHAS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        sha = d_b & 0x1f  # D[b][0:5]
        cond_1 = extend_to_32_bits(sha >= 0)  #
        cond_2 = extend_to_32_bits(sha < 0)   # not work correctly for negative numbers
        result = (d_a << sha.cast_to(Type.int_8)) & cond_1 | \
                 (d_a >> sha.cast_to(Type.int_8)) & cond_2

        return ssov(result, 32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUB_Inst(Instruction):
    """ Subtract instruction.
        op = 0x0B
        op2 = 0x08
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUB'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a - d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

    def compute_flags(self, *args):
        retval = args[-1]
        v = (retval > 0x7FFFFFFF) or (retval < -80000000)
        av = retval[31] ^ retval[30]
        psw_val = self.get_psw()
        # set V & SV
        psw_val = (v).ite(
             psw_val | int("01100000000000000000000000000000", 2),
             psw_val & int("10111111111111111111111111111111", 2)
        )
        # set AV & SAV
        psw_val = (av).ite(
            psw_val | int("00011000000000000000000000000000", 2),
            psw_val & int("11101111111111111111111111111111", 2)
        )
        self.put(psw_val, "psw")

class RR_SUB_A_Inst(Instruction):
    """ Subtract Address instruction.
        op = 0x01
        op2 = 0x02
        User Status Flags: no change
    """
    name = 'RR_SUB.A'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(1)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a - a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUB_B_Inst(Instruction):
    """ Subtract Packed Byte instruction.
        op = 0x0B
        op2 = 0x48
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUB.B'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(4)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_byte_0 = ((d_a & 0xff) - (d_b & 0xff)) & 0xff
        result_byte_1 = (((d_a >>  8) & 0xff) - ((d_b >>  8) & 0xff)) & 0xff
        result_byte_2 = (((d_a >> 16) & 0xff) - ((d_b >> 16) & 0xff)) & 0xff
        result_byte_3 = (((d_a >> 24) & 0xff) - ((d_b >> 24) & 0xff)) & 0xff
        result = (result_byte_3 << 24) | (result_byte_2 << 16) | \
                 (result_byte_1 << 8)  | result_byte_0

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUB_H_Inst(Instruction):
    """ Subtract Packed Half-word instruction.
        op = 0x0B
        op2 = 0x68
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUB.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_hw_0 = ((d_a & 0xffff) - (d_b & 0xffff)) & 0xffff
        result_hw_1 = (((d_a >>  16) & 0xffff) - ((d_b >>  16) & 0xffff)) & 0xffff
        result = (result_hw_1 << 16)  | result_hw_0

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBC_Inst(Instruction):
    """ Subtract with Carry instruction.
        op = 0x0B
        op2 = 0x0D
        User Status Flags: C, V, SV, AV, SAV
    """
    name = 'RR_SUBC'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        psw = self.get_psw()
        psw_c = psw >> 31  # get carry bit
        result = d_a - d_b + psw_c - 1  # result[31:0]

        # set flags
        c = carry(d_a, (d_b^0xffffffff), psw_c)
        v = overflow(result)
        av = advanced_overflow(result)
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBS_Inst(Instruction):
    """ Subtract Signed with Saturation instruction.
        op = 0x0B
        op2 = 0x0A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUBS'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b' * 4 + 'a' * 4 + op2_2 + 'i' * 4 + 'c' * 4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

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

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = ssov32(d_a - d_b, self.max_pos, self.max_neg)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBS_U_Inst(Instruction):
    """ Subtract Unsigned with Saturation instruction.
        op = 0x0B
        op2 = 0x0B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUBS.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = suov32_sub(d_a - d_b)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBS_H_Inst(Instruction):
    """ Subtract Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x6A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUBS.H'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result_hw_0 = (d_a & 0xffff) - (d_b & 0xffff)
        result_hw_1 = ((d_a >> 16) & 0xffff) - ((d_b >> 16) & 0xffff)
        result = (ssov16(result_hw_1) << 16) | ssov16(result_hw_0)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBS_HU_Inst(Instruction):
    """ Subtract Packed Half-word with Saturation instruction.
        op = 0x0B
        op2 = 0x6B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RR_SUBS.HU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        # get each Half-words of registers
        d_a_hw_0 = d_a & 0xffff
        d_a_hw_1 = (d_a >> 16) & 0xffff
        d_b_hw_0 = d_b & 0xffff
        d_b_hw_1 = (d_b >> 16) & 0xffff

        # check if any of them is negative
        cond_d_a_hw_0_neg = extend_to_16_bits((d_a_hw_0 >> 15) == 1)
        cond_d_a_hw_1_neg = extend_to_16_bits((d_a_hw_1 >> 15) == 1)
        cond_d_b_hw_0_neg = extend_to_16_bits((d_b_hw_0 >> 15) == 1)
        cond_d_b_hw_1_neg = extend_to_16_bits((d_b_hw_1 >> 15) == 1)

        # compute complement2 if any of them is negative
        d_a_hw_0_comp = twos_comp_2(d_a_hw_0, 16) & cond_d_a_hw_0_neg
        d_a_hw_1_comp = twos_comp_2(d_a_hw_1, 16) & cond_d_a_hw_1_neg
        d_b_hw_0_comp = twos_comp_2(d_b_hw_0, 16) & cond_d_b_hw_0_neg
        d_b_hw_1_comp = twos_comp_2(d_b_hw_1, 16) & cond_d_b_hw_1_neg

        # get result Half-words
        result_hw_0 = (((d_a_hw_0 - d_b_hw_0) & (~cond_d_a_hw_0_neg) & (~cond_d_b_hw_0_neg)) | \
                      ((d_a_hw_0_comp - d_b_hw_0_comp) & cond_d_a_hw_0_neg & cond_d_b_hw_0_neg))

        result_hw_1 = (((d_a_hw_1 - d_b_hw_1) & (~cond_d_a_hw_1_neg) & (~cond_d_b_hw_1_neg)) | \
                      ((d_a_hw_1_comp - d_b_hw_1_comp) & cond_d_a_hw_1_neg & cond_d_b_hw_1_neg))

        # compute suov16
        result_hw_0_suov = suov16(result_hw_0 & 0xffff)
        result_hw_1_suov = suov16(result_hw_1 & 0xffff)

        # final result
        result = (result_hw_1_suov << 16) | result_hw_0_suov

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_SUBX_Inst(Instruction):
    """ Subtract Extended instruction.
        op = 0x0B
        op2 = 0x0C
        User Status Flags: C, V, SV, AV, SAV
    """
    name = 'RR_SUBX'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a - d_b

        # set flags
        c = carry(d_a, ~d_b, 1)
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XNOR_Inst(Instruction):
    """ Bitwise XNOR instruction.
        op = 0x0F
        op2 = 0x0D
    """
    name = 'RR_XNOR'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return ~(d_a ^ d_b)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_Inst(Instruction):
    """ Bitwise XOR instruction.
        op = 0x0F
        op2 = 0x0C
    """
    name = 'RR_XOR'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'd'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a ^ d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_EQ_Inst(Instruction):
    """ XOR Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x2F
        User Status Flags: no change.
    """
    name = 'RR_XOR.EQ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a == d_b)
        result = ((d_c >> 1) << 1) | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_GE_Inst(Instruction):
    """ XOR Greater Than or Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x33
        User Status Flags: no change.
    """
    name = 'RR_XOR.GE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a >= d_b)         # D[c][0] XOR D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_GE_U_Inst(Instruction):
    """ Greater Than or Equal Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x34
        User Status Flags: no change.
    """
    name = 'RR_XOR.GE.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a >= d_b)         # D[c][0] AND D[a] >= D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_LT_Inst(Instruction):
    """ XOR Less Than Accumulating instruction.
        op = 0x0B
        op2 = 0x31
        User Status Flags: no change.
    """
    name = 'RR_XOR.LT'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a < d_b)          # D[c][0] XOR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_LT_U_Inst(Instruction):
    """ Less Than Accumulating Unsigned instruction.
        op = 0x0B
        op2 = 0x32
        User Status Flags: no change.
    """
    name = 'RR_XOR.LT.U'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        result = self.get("d{0}".format(self.data['c']), Type.int_32)
        return result

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a < d_b)          # D[c][0] XOR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RR_XOR_NE_Inst(Instruction):
    """ OR Not Equal Accumulating instruction.
        op = 0x0B
        op2 = 0x30
        User Status Flags: no change.
    """
    name = 'RR_XOR.NE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_2 + 'i'*4 + 'c'*4 + op2_1

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        bit = d_c[0] ^ (d_a != d_b)         # D[c][0] XOR D[a] < D[b]
        result = ((d_c >> 1) << 1) | bit    # D[c][31:1] | bit
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
