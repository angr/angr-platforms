#!/usr/bin/env python3
""" srr_instr.py
Implementation of SRR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class SRR_ADD_12_Inst(Instruction):
    """ Add instruction.
        op = 0x12
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_ADD_12'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return [self.get_d_15(), self.get_d_b()]

    def compute_result(self, *args):
        d_15 = args[0]
        d_b = args[1]
        result = d_15 + d_b

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

class SRR_ADD_1A_Inst(Instruction):
    """ Add instruction.
        op = 0x1A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_ADD_1A'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a + d_b

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

class SRR_ADD_42_Inst(Instruction):
    """ Add instruction.
        op = 0x42
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_ADD_42'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a + d_b

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

class SRR_ADD_A_Inst(Instruction):
    """ Add instruction.
        op = 0x30
        User Status Flags: no change.
    """
    name = 'SRR_ADD.A'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_a(), self.get_a_b()]

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        return a_a + a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_ADDS_Inst(Instruction):
    """ Add Signed with Saturation instruction.
        op = 0x22
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_ADDS'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT32_MAX_POS, Type.int_32)

    @property
    def max_neg(self):
        return self.constant(INT32_MAX_NEG, Type.int_32)

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = ssov32(d_a + d_b, self.max_pos, self.max_neg)

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

class SRR_AND_Inst(Instruction):
    """ Bitwise AND instruction.
        op = 0x26
        User Status Flags: no change.
    """
    name = 'SRR_AND'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a & d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_CMOV_Inst(Instruction):
    """ Conditional Move instruction.
        op = 0x2A
        User Set Flags: no change.
    """
    name = 'SRR_CMOV'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b(), self.get_d_15()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_15 = args[2]
        condition = d_15 != 0
        return self.irsb_c.ite(condition.rdt, d_b.rdt, d_a.rdt)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_CMOVN_Inst(Instruction):
    """ Conditional Move-Not instruction.
        op = 0x6A
        User Set Flags: no change.
    """
    name = 'SRR_CMOVN'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b(), self.get_d_15()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_15 = args[2]
        condition = d_15 == 0
        return self.irsb_c.ite(condition.rdt, d_b.rdt, d_a.rdt)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_EQ_Inst(Instruction):
    """ Equal instruction.
        op = 0x3A
        User Set Flags: no change.
    """
    name = 'SRR_EQ'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a == d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_LT_Inst(Instruction):
    """ Less Than instruction.
        op = 0x7A
        User Set Flags: no change.
    """
    name = 'SRR_LT'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a < d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_SUB_A2_Inst(Instruction):
    """ Subtract instruction.
        op = 0xA2
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_SUB_A2'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a - d_b

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

class SRR_SUB_52_Inst(Instruction):
    """ Subtract instruction.
        op = 0x52
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_SUB_52'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return [self.get_d_15(), self.get_d_b()]

    def compute_result(self, *args):
        d_15 = args[0]
        d_b = args[1]
        result = d_15 - d_b

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

class SRR_SUB_5A_Inst(Instruction):
    """ Subtract instruction.
        op = 0x5A
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_SUB_5A'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a - d_b

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

class SRR_SUBS_Inst(Instruction):
    """ Subtract Signed with Saturation instruction.
        op = 0x62
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_SUBS'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @property
    def max_pos(self):
        return self.constant(INT32_MAX_POS, Type.int_32)

    @property
    def max_neg(self):
        return self.constant(INT32_MAX_NEG, Type.int_32)

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = ssov32(d_a - d_b, self.max_pos, self.max_neg)

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

class SRR_MOV_Inst(Instruction):
    """ Move instruction.
        op = 0x02
        User Set Flags: no change.
    """
    name = 'SRR_MOV'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        return d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_MOV_A_Inst(Instruction):
    """ Move Value to Address Register instruction.
        op = 0x60
        User Set Flags: no change.
    """
    name = 'SRR_MOV.A'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_b()]

    def compute_result(self, *args):
        d_b = args[0]
        return d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_MOV_D_Inst(Instruction):
    """ Move Address to Data Register instruction.
        op = 0x80
        User Set Flags: no change.
    """
    name = 'SRR_MOV.D'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_MOV_AA_Inst(Instruction):
    """ Move Address from Address Register instruction.
        op = 0x40
        User Set Flags: no change.
    """
    name = 'SRR_MOV.AA'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return a_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_OR_Inst(Instruction):
    """ Bitwise OR instruction.
        op = 0xA6
        User Status Flags: no change.
    """
    name = 'SRR_OR'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a | d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_XOR_Inst(Instruction):
    """ Bitwise XOR instruction.
        op = 0xC6
        User Status Flags: no change.
    """
    name = 'SRR_XOR'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        return d_a ^ d_b

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRR_MUL_Inst(Instruction):
    """ Multiply instruction.
        op = 0xE2
        User Status Flags: V, SV, AV, SAV
    """
    name = 'SRR_MUL'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a(), self.get_d_b()]

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = d_a * d_b

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
