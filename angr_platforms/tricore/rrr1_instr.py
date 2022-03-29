#!/usr/bin/env python3
""" rrr1_instr.py
Implementation of RRR1 format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RRR1_MADD_H_83_1A_Inst(Instruction):
    """ Packed Multiply-Add Q Format instruction:
        op = 0x83
        op2 = 0x1A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.H_83_1A'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADD_H_83_19_Inst(Instruction):
    """ Packed Multiply-Add Q Format instruction:
        op = 0x83
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.H_83_19'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffff)

        e_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w1 = e_d_2 + mul_res1
        result_w0 = e_d_1 + mul_res0

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADD_H_83_18_Inst(Instruction):
    """ Packed Multiply-Add Q Format instruction:
        op = 0x83
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.H_83_18'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADD_H_83_1B_Inst(Instruction):
    """ Packed Multiply-Add Q Format instruction:
        op = 0x83
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.H_83_1B'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDS_H_83_3A_Inst(Instruction):
    """ Packed Multiply-Add Q Format, Saturated instruction:
        op = 0x83
        op2 = 0x3A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.H_83_3A'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0 = ssov32(e_d_0 + mul_res0, max_pos, max_neg)
        result_w1 = ssov32(e_d_1 + mul_res1, max_pos, max_neg)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDS_H_83_39_Inst(Instruction):
    """ Packed Multiply-Add Q Format, Saturated instruction:
        op = 0x83
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.H_83_39'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDS_H_83_38_Inst(Instruction):
    """ Packed Multiply-Add Q Format, Saturated instruction:
        op = 0x83
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.H_83_38'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDS_H_83_3B_Inst(Instruction):
    """ Packed Multiply-Add Q Format, Saturated instruction:
        op = 0x83
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.H_83_3B'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADD_Q_43_02_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x02
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_02'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d + (((d_a * d_b) << n.value) >> 32)

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

class RRR1_MADD_Q_43_1B_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_1B'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * d_b) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADD_Q_43_01_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x01
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_01'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d + (((d_a * (d_b & 0xffff)) << n.value) >> 16)

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

class RRR1_MADD_Q_43_19_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_19'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b & 0xffff)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADD_Q_43_00_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x00
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_00'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d + (((d_a * (d_b >> 16)) << n.value) >> 16)

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

class RRR1_MADD_Q_43_18_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_18'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b >> 16)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADD_Q_43_05_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x05
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_05'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))
        result = d_d + mul_res

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

class RRR1_MADD_Q_43_1D_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_1D'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (mul_res << 16)
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADD_Q_43_04_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x04
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_04'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))
        result = d_d + mul_res

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

class RRR1_MADD_Q_43_1C_Inst(Instruction):
    """ Multiply-Add Q Format instruction:
        op = 0x43
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADD.Q_43_1C'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (mul_res << 16)
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDS_Q_43_22_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x22
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_22'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d + (((d_a * d_b) << n.value) >> 32)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MADDS_Q_43_3B_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_3B'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * d_b) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDS_Q_43_21_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x21
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_21'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d + (((d_a * (d_b & 0xffff)) << n.value) >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MADDS_Q_43_39_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_39'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b & 0xffff)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDS_Q_43_20_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x20
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_20'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d + (((d_a * (d_b >> 16)) << n.value) >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MADDS_Q_43_38_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_38'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b >> 16)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + result_tmp
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDS_Q_43_25_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x25
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_25'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        result1 = d_d + mul_res

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MADDS_Q_43_3D_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_3D'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (mul_res << 16)
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDS_Q_43_24_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x24
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_24'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        result1 = d_d + mul_res

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MADDS_Q_43_3C_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x43
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.Q_43_3C'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (mul_res << 16)
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDM_H_83_1E_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision instruction:
        op = 0x83
        op2 = 0x1E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDM.H_83_1E'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a  & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDM_H_83_1D_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision instruction:
        op = 0x83
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDM.H_83_1D'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDM_H_83_1C_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision instruction:
        op = 0x83
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDM.H_83_1C'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDM_H_83_1F_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision instruction:
        op = 0x83
        op2 = 0x1F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDM.H_83_1F'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDMS_H_83_3E_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision, Saturated instruction:
        op = 0x83
        op2 = 0x3E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDMS.H_83_3E'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a  & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDMS_H_83_3D_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision, Saturated instruction:
        op = 0x83
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDMS.H_83_3D'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 0xffff)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDMS_H_83_3C_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision, Saturated instruction:
        op = 0x83
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDMS.H_83_3C'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 0xffff)  # TODO: >> 16

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDMS_H_83_3F_Inst(Instruction):
    """ Packed Multiply-Add Q Format Multi-precision, Saturated instruction:
        op = 0x83
        op2 = 0x3F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDMS.H_83_3F'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffff))
        sum1 = result_w1 + result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDR_H_83_0E_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0x83
        op2 = 0x0E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_83_0E'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        mul_res0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDR_H_83_0D_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0x83
        op2 = 0x0D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_83_0D'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        mul_res0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff))

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDR_H_83_0C_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0x83
        op2 = 0x0C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_83_0C'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff))
        mul_res0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDR_H_43_1E_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0x43
        op2 = 0x1E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_43_1E'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff))
        mul_res0 = (0x7fffffff & sc0) | (((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_hw0 = e_d_0 + mul_res0 + 0x8000
        result_hw1 = e_d_1 + mul_res1 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDR_H_83_0F_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0x83
        op2 = 0x0F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_83_0F'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDRS_H_83_2E_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x83
        op2 = 0x2E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.H_83_2E'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = ((d_d & 0xffff0000) + mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDRS_H_83_2D_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x83
        op2 = 0x2D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.H_83_2D'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_hw1_ssov = ssov32(result_hw1, max_pos, max_neg)
        result_hw0_ssov = ssov32(result_hw0, max_pos, max_neg)

        result = (result_hw1_ssov & 0xffff0000) | (result_hw0_ssov >> 16)

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

class RRR1_MADDRS_H_83_2C_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x83
        op2 = 0x2C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.H_83_2C'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = ((d_d & 0xffff0000) + mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDRS_H_43_3E_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x43
        op2 = 0x3E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.H_43_3E'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff))
        mul_res0 = (0x7fffffff & sc0) | (((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_hw0 = (e_d_0 + mul_res0 + 0x8000).cast_to(Type.int_64)
        result_hw1 = (e_d_1 + mul_res1 + 0x8000).cast_to(Type.int_64)

        # compute ssov
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDRS_H_83_2F_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x83
        op2 = 0x2F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.H_83_2F'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = ((d_d & 0xffff0000) + mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)

        # compute ssov
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)

        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDR_Q_43_07_Inst(Instruction):
    """ Multiply-Add Q Format with Rounding instruction:
        op = 0x43
        op2 = 0x07
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.Q_43_07'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(7)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffffffff))
        result = (d_d + mul_res + 0x8000) & 0xffff0000

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

class RRR1_MADDR_Q_43_06_Inst(Instruction):
    """ Multiply-Add Q Format with Rounding instruction:
        op = 0x43
        op2 = 0x06
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.Q_43_06'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffffffff))
        result = (d_d + mul_res + 0x8000) & 0xffff0000

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

class RRR1_MADDRS_Q_43_27_Inst(Instruction):
    """ Multiply-Add Q Format with Rounding instruction:
        op = 0x43
        op2 = 0x27
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.Q_43_27'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(7)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffffffff))
        sum_tmp = (d_d + mul_res + 0x8000).cast_to(Type.int_64)
        sum_tmp_ssov = ssov32(sum_tmp, self.max_pos, self.max_neg)
        result = sum_tmp_ssov & 0xffff0000

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDRS_Q_43_26_Inst(Instruction):
    """ Multiply-Add Q Format with Rounding, Saturated instruction:
        op = 0x43
        op2 = 0x26
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDRS.Q_43_26'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc^0xffffffff))
        sum_tmp = (d_d + mul_res + 0x8000).cast_to(Type.int_64)
        sum_tmp_ssov = ssov32(sum_tmp, self.max_pos, self.max_neg)
        result = sum_tmp_ssov & 0xffff0000

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR1_MADDSU_H_C3_1A_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x1A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSU.H_C3_1A'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSU_H_C3_19_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSU.H_C3_19'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSU_H_C3_18_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSU.H_C3_18'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSU_H_C3_1B_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSU.H_C3_1B'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSUS_H_C3_3A_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x3A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUS.H_C3_3A'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSUS_H_C3_39_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDS.H_C3_39'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSUS_H_C3_38_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUS.H_C3_38'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSUS_H_C3_3B_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format instruction:
        op = 0xC3
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUS.H_C3_3B'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 + mul_res1

        # compute ssov
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MADDSUM_H_C3_1E_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision instruction:
        op = 0xC3
        op2 = 0x1E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUM.H_C3_1E'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDSUM_H_C3_1D_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision instruction:
        op = 0xC3
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUM.H_C3_1D'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDSUM_H_C3_1C_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision instruction:
        op = 0xC3
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUM.H_C3_1C'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDSUM_H_C3_1F_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision instruction:
        op = 0x83
        op2 = 0x1F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUM.H_C3_1F'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MADDSUMS_H_C3_3E_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision, Saturated instruction:
        op = 0xC3
        op2 = 0x3E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUMS.H_C3_3E'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1_ssov
        result <<= 32
        result |= result_w0_ssov

        # set flags
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

class RRR1_MADDSUMS_H_C3_3D_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision, Saturated instruction:
        op = 0xC3
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUMS.H_C3_3D'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1_ssov
        result <<= 32
        result |= result_w0_ssov

        # set flags
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

class RRR1_MADDSUMS_H_C3_3C_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision, Saturated instruction:
        op = 0xC3
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUMS.H_C3_3C'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff))
        sum1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sum1 << 16)
        result_w1 = e_d_1 + (sum1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1_ssov
        result <<= 32
        result |= result_w0_ssov

        # set flags
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

class RRR1_MADDSUMS_H_C3_3F_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format Multi-precision, Saturated instruction:
        op = 0xC3
        op2 = 0x3F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUMS.H_C3_3F'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))

        result_w1 = (0x7fffffff & sc1) | ((((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff))
        result_w0 = (0x7fffffff & sc0) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff))
        sub1 = result_w1 - result_w0

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 + (sub1 << 16)
        result_w1 = e_d_1 + (sub1 >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1_ssov
        result <<= 32
        result |= result_w0_ssov

        # set flags
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

class RRR1_MADDSUR_H_C3_0E_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding instruction:
        op = 0xC3
        op2 = 0x0E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUR.H_C3_0E'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDSUR_H_C3_0D_Inst(Instruction):
    """ Packed Multiply-Add Q Format with Rounding instruction:
        op = 0xC3
        op2 = 0x0D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDR.H_C3_0D'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDSUR_H_C3_0C_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding instruction:
        op = 0xC3
        op2 = 0x0C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUR.H_C3_0C'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDSUR_H_C3_0F_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding instruction:
        op = 0xC3
        op2 = 0x0F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSUR.H_C3_0F'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)

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

class RRR1_MADDSURS_H_C3_2E_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding, Saturated instruction:
        op = 0xC3
        op2 = 0x2E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSURS.H_C3_2E'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_hw1_ssov = ssov32(result_hw1, max_pos, max_neg)
        result_hw0_ssov = ssov32(result_hw0, max_pos, max_neg)

        result = (result_hw1_ssov & 0xffff0000) | (result_hw0_ssov >> 16)

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

class RRR1_MADDSURS_H_C3_2D_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding, Saturated instruction:
        op = 0xC3
        op2 = 0x2D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSURS.H_C3_2D'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_hw1_ssov = ssov32(result_hw1, max_pos, max_neg)
        result_hw0_ssov = ssov32(result_hw0, max_pos, max_neg)

        result = (result_hw1_ssov & 0xffff0000) | (result_hw0_ssov >> 16)

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

class RRR1_MADDSURS_H_C3_2C_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding, Saturated instruction:
        op = 0xC3
        op2 = 0x2C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSURS.H_C3_2C'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_hw1_ssov = ssov32(result_hw1, max_pos, max_neg)
        result_hw0_ssov = ssov32(result_hw0, max_pos, max_neg)
        result = (result_hw1_ssov & 0xffff0000) | (result_hw0_ssov >> 16)

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

class RRR1_MADDSURS_H_C3_2F_Inst(Instruction):
    """ Packed Multiply-Add/Subtract Q Format with Rounding, Saturated instruction:
        op = 0xC3
        op2 = 0x2F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MADDSURS.H_C3_2F'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        d_d = self.get("d{0}".format(self.data['d']), Type.int_32)
        result_hw1 = (d_d & 0xffff0000) + mul_res1 + 0x8000
        result_hw0 = (d_d << 16) - mul_res0 + 0x8000

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_hw0_ssov = ssov32(result_hw0, max_pos, max_neg)
        result_hw1_ssov = ssov32(result_hw1, max_pos, max_neg)

        result = (result_hw1_ssov & 0xffff0000) | (result_hw0_ssov >> 16)

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

class RRR1_MSUB_H_A3_1A_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format instruction:
        op = 0xA3
        op2 = 0x1A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.H_A3_1A'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUB_H_A3_19_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format instruction:
        op = 0xA3
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.H_A3_19'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUB_H_A3_18_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format instruction:
        op = 0xA3
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.H_A3_18'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUB_H_A3_1B_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format instruction:
        op = 0xA3
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.H_A3_1B'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_H_A3_3A_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format, Saturated instruction:
        op = 0xA3
        op2 = 0x3A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.H_A3_3A'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = (((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = (((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0 = ssov32(e_d_0 - mul_res0, max_pos, max_neg)
        result_w1 = ssov32(e_d_1 - mul_res1, max_pos, max_neg)

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_H_A3_39_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format, Saturated instruction:
        op = 0xA3
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.H_A3_39'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b & 0xffff)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_H_A3_38_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format, Saturated instruction:
        op = 0xA3
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.H_A3_38'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_H_A3_3B_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format, Saturated instruction:
        op = 0xA3
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.H_A3_3B'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | (((d_a & 0xffff) * (d_b >> 16)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | (((d_a >> 16) * (d_b >> 16)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        result_w0 = e_d_0 - mul_res0
        result_w1 = e_d_1 - mul_res1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0_ssov)
        ov_w1 = overflow(result_w1_ssov)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0_ssov)
        aov_w1 = advanced_overflow(result_w1_ssov)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUB_Q_63_02_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x02
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_02'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d - (((d_a * d_b) << n.value) >> 32)

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

class RRR1_MSUB_Q_63_1B_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_1B'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * d_b) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUB_Q_63_01_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x01
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_01'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d - (((d_a * (d_b & 0xffff)) << n.value) >> 16)

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

class RRR1_MSUB_Q_63_19_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_19'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b & 0xffff)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUB_Q_63_00_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x00
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_00'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result = d_d - (((d_a * (d_b >> 16)) << n.value) >> 16)

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

class RRR1_MSUB_Q_63_18_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_18'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b >> 0xffff)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - result_tmp
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUB_Q_63_05_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x05
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_05'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))
        result = d_d - mul_res

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

class RRR1_MSUB_Q_63_1D_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_1D'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - (mul_res << 16)
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUB_Q_63_04_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x04
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_04'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))
        result = d_d - mul_res

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

class RRR1_MSUB_Q_63_1C_Inst(Instruction):
    """ Multiply-Subtract Q Format instruction:
        op = 0x63
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUB.Q_63_1C'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - (mul_res << 16)
        result_w1 = e_d_1

        # put results
        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUBS_Q_63_22_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x22
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_22'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d - (((d_a * d_b) << n.value) >> 32)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MSUBS_Q_63_3B_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_3B'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * d_b) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        d_d_64_bit = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result_64_bit = d_d_64_bit - result_tmp.cast_to(Type.int_64)
        result_w0 = (result_64_bit & 0xffffffff).cast_to(Type.int_32)
        result_w1 = (result_64_bit >> 32).cast_to(Type.int_32)

        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        v = overflow_64(result_64_bit).cast_to(Type.int_32)
        av = advanced_overflow_64(result_64_bit).cast_to(Type.int_32)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_Q_63_21_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x21
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_21'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d - (((d_a * (d_b & 0xffff)) << n.value) >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MSUBS_Q_63_39_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_39'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b & 0xffff)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        d_d_64_bit = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result_64_bit = d_d_64_bit - result_tmp.cast_to(Type.int_64)
        result_w0 = (result_64_bit & 0xffffffff).cast_to(Type.int_32)
        result_w1 = (result_64_bit >> 32).cast_to(Type.int_32)

        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        v = overflow_64(result_64_bit).cast_to(Type.int_32)
        av = advanced_overflow_64(result_64_bit).cast_to(Type.int_32)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_Q_63_20_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x20
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_20'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        result1 = d_d - (((d_a * (d_b >> 16)) << n.value) >> 16)

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MSUBS_Q_63_38_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_38'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result_tmp = (d_a * (d_b >> 16)) << n.value

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]
        result_w0 = e_d_0 - result_tmp
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUBS_Q_63_25_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x25
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_25'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        result1 = d_d - mul_res

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MSUBS_Q_63_3D_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_3D'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a & 0xffff) * (d_b & 0xffff)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        d_d_64_bit = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result_64_bit = d_d_64_bit - (mul_res.cast_to(Type.int_64) << 16)
        result_w0 = (result_64_bit & 0xffffffff).cast_to(Type.int_32)
        result_w1 = (result_64_bit >> 32).cast_to(Type.int_32)

        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        v = overflow_64(result_64_bit).cast_to(Type.int_32)
        av = advanced_overflow_64(result_64_bit).cast_to(Type.int_32)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBS_Q_63_24_Inst(Instruction):
    """ Multiply-Subtract Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x24
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_24'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        result1 = d_d - mul_res

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(result1, max_pos, max_neg)

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

class RRR1_MSUBS_Q_63_3C_Inst(Instruction):
    """ Multiply-Add Q Format, Saturated instruction:
        op = 0x63
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBS.Q_63_3C'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc = extend_to_16_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res = (0x7fffffff & sc) | ((((d_a >> 16) * (d_b >> 16)) << n.value) & (sc^0xffff))

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][62:32]

        result_w0 = e_d_0 - (mul_res << 16)
        result_w1 = e_d_1

        # compute ssov32
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result_w0_ssov = ssov32(result_w0, max_pos, max_neg)
        result_w1_ssov = ssov32(result_w1, max_pos, max_neg)

        # put results
        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # prepare 64-bit object for setting flags
        result = result_w1
        result <<= 32
        result |= result_w0

        # set flags
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

class RRR1_MSUBAD_H_E3_1A_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format instruction:
        op = 0xE3
        op2 = 0x1A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBAD.H_E3_1A'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = e_d_1 - mul_res1
        result_w0 = e_d_0 + mul_res0

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBAD_H_E3_19_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format instruction:
        op = 0xE3
        op2 = 0x19
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBAD.H_E3_19'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = e_d_1 - mul_res1
        result_w0 = e_d_0 + mul_res0

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBAD_H_E3_18_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format instruction:
        op = 0xE3
        op2 = 0x18
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBAD.H_E3_18'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = e_d_1 - mul_res1
        result_w0 = e_d_0 + mul_res0

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBAD_H_E3_1B_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format instruction:
        op = 0xE3
        op2 = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBAD.H_E3_1B'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = e_d_1 - mul_res1
        result_w0 = e_d_0 + mul_res0

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADS_H_E3_3A_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format, Saturated instruction:
        op = 0xE3
        op2 = 0x3A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADS.H_E3_3A'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = ssov32(e_d_1 - mul_res1, self.max_pos, self.max_neg)
        result_w0 = ssov32(e_d_0 + mul_res0, self.max_pos, self.max_neg)

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_w0)
        ov_w1 = overflow(result_w1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_w0)
        aov_w1 = advanced_overflow(result_w1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADS_H_E3_39_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format, Saturated instruction:
        op = 0xE3
        op2 = 0x39
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADS.H_E3_39'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = (e_d_1 - mul_res1).cast_to(Type.int_64)
        result_w0 = (e_d_0 + mul_res0).cast_to(Type.int_64)
        result_w1_ssov = ssov32(result_w1, self.max_pos, self.max_neg)
        result_w0_ssov = ssov32(result_w0, self.max_pos, self.max_neg)

        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow_64(result_w0).cast_to(Type.int_32)
        ov_w1 = overflow_64(result_w1).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow_64(result_w0).cast_to(Type.int_32)
        aov_w1 = advanced_overflow_64(result_w1).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADS_H_E3_38_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format, Saturated instruction:
        op = 0xE3
        op2 = 0x38
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADS.H_E3_38'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = (e_d_1 - mul_res1).cast_to(Type.int_64)
        result_w0 = (e_d_0 + mul_res0).cast_to(Type.int_64)
        result_w1_ssov = ssov32(result_w1, self.max_pos, self.max_neg)
        result_w0_ssov = ssov32(result_w0, self.max_pos, self.max_neg)

        self.put(result_w0_ssov, "d{0}".format(self.data['c']))
        self.put(result_w1_ssov, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow_64(result_w0).cast_to(Type.int_32)
        ov_w1 = overflow_64(result_w1).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow_64(result_w0).cast_to(Type.int_32)
        aov_w1 = advanced_overflow_64(result_w1).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADS_H_E3_3B_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format, Saturated instruction:
        op = 0xE3
        op2 = 0x3B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADS.H_E3_3B'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xb)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        result_w1 = (e_d_1 - mul_res1).cast_to(Type.int_64)
        result_w0 = (e_d_0 + mul_res0).cast_to(Type.int_64)

        self.put(result_w0, "d{0}".format(self.data['c']))
        self.put(result_w1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow_64(result_w0).cast_to(Type.int_32)
        ov_w1 = overflow_64(result_w1).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow_64(result_w0).cast_to(Type.int_32)
        aov_w1 = advanced_overflow_64(result_w1).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADM_H_E3_1E_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision instruction:
        op = 0xE3
        op2 = 0x1E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADM.H_E3_1E'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((result_word1 - result_word0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)

        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADM_H_E3_1D_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision instruction:
        op = 0xE3
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADM.H_E3_1D'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((result_word1 - result_word0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADM_H_E3_1C_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision instruction:
        op = 0xE3
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADM.H_E3_1C'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((result_word1 - result_word0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADM_H_E3_1F_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision instruction:
        op = 0xE3
        op2 = 0x1F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADM.H_E3_1F'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((result_word1 - result_word0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADMS_H_E3_3E_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision, Saturated instruction:
        op = 0xE3
        op2 = 0x3E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADMS.H_E3_3E'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sub_words = (result_word1 - result_word0).cast_to(Type.int_64) << 16
        result = e_d - sub_words
        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sub_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)

        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADMS_H_E3_3D_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision, Saturated instruction:
        op = 0xE3
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADMS.H_E3_3D'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sub_words = (result_word1 - result_word0).cast_to(Type.int_64) << 16
        result = e_d - sub_words
        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sub_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADMS_H_E3_3C_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision, Saturated instruction:
        op = 0xE3
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADMS.H_E3_3C'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sub_words = (result_word1 - result_word0).cast_to(Type.int_64) << 16
        result = e_d - sub_words
        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sub_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADMS_H_E3_3F_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format-Multi-precision, Saturated instruction:
        op = 0xE3
        op2 = 0x3F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADMS.H_E3_3F'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        result_word1 = ((0x7fffffff & sc1) | \
                        ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                        (sc1^0xffffffff)).cast_to(Type.int_64)
        result_word0 = ((0x7fffffff & sc0) | \
                        ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                        (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sub_words = (result_word1 - result_word0).cast_to(Type.int_64) << 16
        result = e_d - sub_words
        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sub_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADR_H_E3_0E_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding instruction:
        op = 0xE3
        op2 = 0x0E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADR.H_E3_0E'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        result_hw1 = (d_d & 0xffff0000) - mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result)
        ov_w1 = overflow(result)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result)
        aov_w1 = advanced_overflow(result)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADR_H_E3_0D_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding instruction:
        op = 0xE3
        op2 = 0x0D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADR.H_E3_0D'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        result_hw1 = (d_d & 0xffff0000) - mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result)
        ov_w1 = overflow(result)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result)
        aov_w1 = advanced_overflow(result)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADR_H_E3_0C_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding instruction:
        op = 0xE3
        op2 = 0x0C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADR.H_E3_0C'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        result_hw1 = (d_d & 0xffff0000) - mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result)
        ov_w1 = overflow(result)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result)
        aov_w1 = advanced_overflow(result)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADR_H_E3_0F_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding instruction:
        op = 0xE3
        op2 = 0x0F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADR.H_E3_0F'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        result_hw1 = (d_d & 0xffff0000) - mul_res1 + 0x8000
        result_hw0 = (d_d << 16) + mul_res0 + 0x8000
        result = (result_hw1 & 0xffff0000) | (result_hw0 >> 16)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result)
        ov_w1 = overflow(result)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result)
        aov_w1 = advanced_overflow(result)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADRS_H_E3_2E_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding, Saturated instruction:
        op = 0xE3
        op2 = 0x2E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADRS.H_E3_2E'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        result_hw1 = ((d_d & 0xffff0000) - mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result).cast_to(Type.int_32)
        ov_w1 = overflow(result).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result).cast_to(Type.int_32)
        aov_w1 = advanced_overflow(result).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADRS_H_E3_2D_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding, Saturated instruction:
        op = 0xE3
        op2 = 0x2D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADRS.H_E3_2D'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        result_hw1 = ((d_d & 0xffff0000) - mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result).cast_to(Type.int_32)
        ov_w1 = overflow(result).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result).cast_to(Type.int_32)
        aov_w1 = advanced_overflow(result).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADRS_H_E3_2C_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding, Saturated instruction:
        op = 0xE3
        op2 = 0x2C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADRS.H_E3_2C'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (sc0^0xffffffff)

        result_hw1 = ((d_d & 0xffff0000) - mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result).cast_to(Type.int_32)
        ov_w1 = overflow(result).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result).cast_to(Type.int_32)
        aov_w1 = advanced_overflow(result).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBADRS_H_E3_2F_Inst(Instruction):
    """ Packed Multiply-Subtract/Add Q Format with Rounding, Saturated instruction:
        op = 0xE3
        op2 = 0x2F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBADRS.H_E3_2F'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(2)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

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

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        n = args[3]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = (0x7fffffff & sc1) | ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (sc1^0xffffffff)
        mul_res0 = (0x7fffffff & sc0) | ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (sc0^0xffffffff)

        result_hw1 = ((d_d & 0xffff0000) - mul_res1 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw0 = ((d_d << 16) + mul_res0 + 0x8000).cast_to(Type.int_64, signed=True)
        result_hw1_ssov = ssov32(result_hw1, self.max_pos, self.max_neg)
        result_hw0_ssov = ssov32(result_hw0, self.max_pos, self.max_neg)
        result = (result_hw1_ssov & 0xffff0000) | ((result_hw0_ssov >> 16) & 0xffff)
        self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        ov_w0 = overflow(result).cast_to(Type.int_32)
        ov_w1 = overflow(result).cast_to(Type.int_32)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result).cast_to(Type.int_32)
        aov_w1 = advanced_overflow(result).cast_to(Type.int_32)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBM_H_A3_1E_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision instruction:
        op = 0xA3
        op2 = 0x1E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBM.H_A3_1E'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((mul_res1 + mul_res0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBM_H_A3_1D_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision instruction:
        op = 0xA3
        op2 = 0x1D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBM.H_A3_1D'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((mul_res1 + mul_res0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBM_H_A3_1C_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision instruction:
        op = 0xA3
        op2 = 0x1C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBM.H_A3_1C'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((mul_res1 + mul_res0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBM_H_A3_1F_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision instruction:
        op = 0xA3
        op2 = 0x1F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBM.H_A3_1F'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        result = e_d - ((mul_res1 + mul_res0) << 16)

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBMS_H_A3_3E_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision, Saturated instruction:
        op = 0xA3
        op2 = 0x3E
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBMS.H_A3_3E'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sum_words = (mul_res1 + mul_res0) << 16
        result = e_d - sum_words

        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sum_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))       # E[c][31:0]
        self.put(result_1, "d{0}".format(self.data['c']+1))     # E[c][63:32]

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBMS_H_A3_3D_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision, Saturated instruction:
        op = 0xA3
        op2 = 0x3D
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBMS.H_A3_3D'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sum_words = (mul_res1 + mul_res0) << 16
        result = e_d - sum_words

        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sum_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBMS_H_A3_3C_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision, Saturated instruction:
        op = 0xA3
        op2 = 0x3C
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBMS.H_A3_3C'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b & 0xffff) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sum_words = (mul_res1 + mul_res0) << 16
        result = e_d - sum_words

        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sum_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RRR1_MSUBMS_H_A3_3F_Inst(Instruction):
    """ Packed Multiply-Subtract Q Format-Multi-precision, Saturated instruction:
        op = 0xA3
        op2 = 0x3F
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR1_MSUBMS.H_A3_3F'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(3)[2:].zfill(2))
    op2_2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'n'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT64_MAX_POS, Type.int_64)

    @property
    def max_neg(self):
        return self.constant(INT64_MAX_NEG, Type.int_64)

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
        mul_res1 = ((0x7fffffff & sc1) | \
                    ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) &
                    (sc1^0xffffffff)).cast_to(Type.int_64)
        mul_res0 = ((0x7fffffff & sc0) | \
                    ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) &
                    (sc0^0xffffffff)).cast_to(Type.int_64)

        e_d_0 = self.get("d{0}".format(self.data['d']), Type.int_32)    # E[d][31:0]
        e_d_1 = self.get("d{0}".format(self.data['d']+1), Type.int_32)  # E[d][63:32]
        e_d = (e_d_1.cast_to(Type.int_64) << 32) | e_d_0.cast_to(Type.int_64)
        sum_words = (mul_res1 + mul_res0) << 16
        result = e_d - sum_words

        # compute SSOV64
        ovf_val = (result ^ e_d) & (e_d ^ sum_words)
        cond_ovf_neg = extend_bits((ovf_val<0), 64)
        cond_e_d_pos = extend_bits((e_d >= 0), 64)
        result = (self.max_pos & cond_ovf_neg & cond_e_d_pos) | \
                 (self.max_neg & cond_ovf_neg & (cond_e_d_pos^0xffffffffffffffff)) | \
                 (result & (cond_ovf_neg^0xffffffffffffffff))

        result_0 = (result & 0xffffffff).cast_to(Type.int_32)
        result_1 = (result >> 32).cast_to(Type.int_32)
        self.put(result_0, "d{0}".format(self.data['c']))
        self.put(result_1, "d{0}".format(self.data['c']+1))

        # set flags
        c = 0
        ov_w0 = overflow(result_0)
        ov_w1 = overflow(result_1)
        v = ov_w1 | ov_w0
        aov_w0 = advanced_overflow(result_0)
        aov_w1 = advanced_overflow(result_1)
        av = aov_w1 | aov_w0
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")
