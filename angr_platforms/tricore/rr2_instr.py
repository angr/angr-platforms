#!/usr/bin/env python3
""" rr2_instr.py
Implementation of RR2 format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RR2_MUL_Inst(Instruction):
    """ Multiply instruction.
        op = 0x73
        op2 = 0x0A
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR2_MUL'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'i'*4

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
        result = d_a.cast_to(Type.int_64) * d_b.cast_to(Type.int_64)
        result = result & 0xffffffff

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

class RR2_MULS_Inst(Instruction):
    """ Multiply, Saturated instruction.
        op = 0x73
        op2 = 0x8A
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR2_MULS'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

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

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result1 = d_a.cast_to(Type.int_64, signed=True) * d_b.cast_to(Type.int_64, signed=True)
        result = ssov32(result1, self.max_pos, self.max_neg)

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

class RR2_MUL_6A_Inst(Instruction):
    """ Multiply instruction.
        op = 0x73
        op2 = 0x6A
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR2_MUL_6A.U'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

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
        result = d_a.cast_to(Type.int_64) * d_b.cast_to(Type.int_64)
        result_1 = result.cast_to(Type.int_32) & 0xffffffff
        result_2 = (result >> 32).cast_to(Type.int_32)
        self.put(result_1, "d{0}".format(self.data['c']))
        self.put(result_2, "d{0}".format(self.data['c']+1))

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

class RR2_MUL_U_Inst(Instruction):
    """ Multiply Unsigned instruction.
        op = 0x73
        op2 = 0x68
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR2_MUL.U'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(6)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

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
        result = d_a.cast_to(Type.int_64) * d_b.cast_to(Type.int_64)
        result_1 = result.cast_to(Type.int_32) & 0xffffffff
        result_2 = (result >> 32).cast_to(Type.int_32)
        self.put(result_1, "d{0}".format(self.data['c']))
        self.put(result_2, "d{0}".format(self.data['c']+1))

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

class RR2_MULS_U_Inst(Instruction):
    """ Multiply Unsigned, Saturated instruction.
        op = 0x73
        op2 = 0x88
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RR2_MULS.U'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(3)[2:].zfill(4))
    op2_1 = "{0}".format(bin(8)[2:].zfill(4))
    op2_2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2_1 + op2_2 + 'c'*4 + 'i'*4

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
        result = d_a.cast_to(Type.int_64) * d_b.cast_to(Type.int_64)  # Unsigned
        result = suov32(result)

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
