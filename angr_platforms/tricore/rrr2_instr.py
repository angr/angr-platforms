#!/usr/bin/env python3
""" rrr2_instr.py
Implementation of RRR2 format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RRR2_MADD_32_Inst(Instruction):
    """ Multiply-Add 32-bit instruction:
        op = 0x03
        op2 = 0x0A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADD_32'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        result = d_d + (d_a * d_b)

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

class RRR2_MADD_64_Inst(Instruction):
    """ Multiply-Add 64-bit instruction:
        op = 0x03
        op2 = 0x6A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADD_64'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = e_d + (d_a_64bit * d_b_64bit)

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MADD_U_64_Inst(Instruction):
    """ Multiply-Add Unsigned 64-bit instruction:
        op = 0x03
        op2 = 0x68
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADD.U_64'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = e_d + (d_a_64bit * d_b_64bit)  # Unsigned

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MADDS_32_Inst(Instruction):
    """ Multiply-Add, Saturated 32-bit instruction:
        op = 0x03
        op2 = 0x8A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADDS_32'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(d_d + (d_a * d_b), max_pos, max_neg)

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

class RRR2_MADDS_64_Inst(Instruction):
    """ Multiply-Add, Saturated 64-bit instruction:
        op = 0x03
        op2 = 0xEA
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADDS_64'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0xe)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = ssov64(e_d + (d_a_64bit * d_b_64bit))

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MADDS_U_32_Inst(Instruction):
    """ Multiply-Add Unsigned, Saturated 32-bit instruction:
        op = 0x03
        op2 = 0x88
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADDS.U_32'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        result = suov32(d_d + (d_a * d_b))  # Unsigned

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

class RRR2_MADDS_U_64_Inst(Instruction):
    """ Multiply-Add Unsigned, Saturated 64-bit instruction:
        op = 0x03
        op2 = 0xE8
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MADDS.U_64'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0xe)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = suov64(e_d + (d_a_64bit * d_b_64bit))

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MSUB_32_Inst(Instruction):
    """ Multiply-Subtract 32-bit instruction:
        op = 0x23
        op2 = 0x0A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUB_32'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        result = d_d - (d_a * d_b)

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

class RRR2_MSUB_64_Inst(Instruction):
    """ Multiply-Subtract 64-bit instruction:
        op = 0x23
        op2 = 0x6A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUB_64'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = e_d - (d_a_64bit * d_b_64bit)

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MSUBS_32_Inst(Instruction):
    """ Multiply-Subtract, Saturated 32-bit instruction:
        op = 0x23
        op2 = 0x8A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUBS_32'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(d_d - (d_a * d_b), max_pos, max_neg)

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

class RRR2_MSUBS_64_Inst(Instruction):
    """ Multiply-Subtract, Saturated 64-bit instruction:
        op = 0x23
        op2 = 0xEA
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUBS_64'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0xe)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = ssov64(e_d - (d_a_64bit * d_b_64bit))

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MSUB_U_64_Inst(Instruction):
    """ Multiply-Subtract Unsigned 64-bit instruction:
        op = 0x23
        op2 = 0x68
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUB.U_64'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = e_d - (d_a_64bit * d_b_64bit)  # Unsigned operators

        # put results
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32
        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR2_MSUBS_U_32_Inst(Instruction):
    """ Multiply-Subtract Unsigned, Saturated 32-bit instruction:
        op = 0x23
        op2 = 0x88
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUBS.U_32'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        max_pos = self.constant(INT32_MAX_POS, Type.int_32)
        max_neg = self.constant(INT32_MAX_NEG, Type.int_32)
        result = ssov32(d_d - (d_a * d_b), max_pos, max_neg)
        # convert to unsigned
        unsigned_cond = extend_to_32_bits(result & 0x80000000 == 0x80000000)
        result = result & (unsigned_cond ^ 0xffffffff)

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

class RRR2_MSUBS_U_64_Inst(Instruction):
    """ Multiply-Subtract Unsigned, Saturated 64-bit instruction:
        op = 0x23
        op2 = 0xE8
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR2_MSUBS.U_64'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0xe)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

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
        d_d_1 = self.get("d{0}".format(self.data['d']), Type.int_32)
        d_d_2 = self.get("d{0}".format(self.data['d']+1), Type.int_32)
        e_d = self.constant(0, Type.int_64)  # 64-bit object
        e_d |= d_d_2.cast_to(Type.int_64)
        e_d <<= 32
        e_d |= d_d_1.cast_to(Type.int_64)
        d_a_64bit = d_a.cast_to(Type.int_64)
        d_b_64bit = d_b.cast_to(Type.int_64)

        result = ssov64(e_d - (d_a_64bit * d_b_64bit))

        # prepare results for 32-bit registers
        result_d_c_1 = result & 0xffffffff
        result_d_c_2 = result >> 32

        # convert to unsigned
        unsigned_cond_1 = extend_to_32_bits(result_d_c_1 & 0x80000000 == 0x80000000)
        result_d_c_1 = result_d_c_1 & (unsigned_cond_1 ^ 0xffffffff)
        unsigned_cond_2 = extend_to_32_bits(result_d_c_2 & 0x80000000 == 0x80000000)
        result_d_c_2 = result_d_c_2 & (unsigned_cond_2 ^ 0xffffffff)

        self.put(result_d_c_1, "d{0}".format(self.data['c']))
        self.put(result_d_c_2, "d{0}".format(self.data['c']+1))

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
