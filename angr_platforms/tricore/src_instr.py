#!/usr/bin/env python3
""" src_instr.py
Implementation of SRC format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class SRC_ADD_92_Inst(Instruction):
    """ Add instruction.
        op = 0x92
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SRC_ADD_92'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_const4()

    def compute_result(self, *args):
        d_15 = args[0]
        const4 = args[1]
        result = d_15 + const4

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

class SRC_ADD_9A_Inst(Instruction):
    """ Add instruction.
        op = 0x9A
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SRC_ADD_9A'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        result = d_a + const4

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

class SRC_ADD_C2_Inst(Instruction):
    """ Add instruction.
        op = 0xC2
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SRC_ADD_C2'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        result = (d_a + const4) & 0xffffffff

        c = 0
        v = (result >> 32 != 0)
        sv = v
        av = result[31] ^ result[30]
        sav = av
        psw = self.get_psw()
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_ADD_A_Inst(Instruction):
    """ Add instruction.
        op = 0xB0
        User Status Flags: no change.
    """
    name = 'SRC_ADD.A'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_const4()

    def compute_result(self, *args):
        a_a = args[0]
        const4 = args[1]
        return a_a + const4

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_CADD_Inst(Instruction):
    """ Conditional Add instruction.
        op = 0x8A
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SRC_CADD'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_15(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_15 = args[1]
        const4 = args[2]
        condition = extend_to_32_bits(d_15 != 0)
        result = ((d_a + const4) & condition) | (d_a & ~condition)

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

class SRC_CADDN_Inst(Instruction):
    """ Conditional Add-Not instruction.
        op = 0xCA
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SRC_CADDN'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_15(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_15 = args[1]
        const4 = args[2]
        condition = extend_to_32_bits(d_15 == 0)
        result = ((d_a + const4) & condition) | (d_a & ~condition)

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

class SRC_CMOV_Inst(Instruction):
    """ Conditional Move instruction.
        op = 0xAA
        User Status Flags: no change.
    """
    name = 'SRC_CMOV'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_15(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_15 = args[1]
        const4 = args[2]
        condition = extend_to_32_bits(d_15 != 0)
        result = (const4 & condition) | (d_a & ~condition)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_CMOVN_Inst(Instruction):
    """ Conditional Move-Not instruction.
        op = 0xEA
        User Status Flags: no change.
    """
    name = 'SRC_CMOVN'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_15(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_15 = args[1]
        const4 = args[2]
        condition = extend_to_32_bits(d_15 == 0)
        result = (const4 & condition) | (d_a & ~condition)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_EQ_Inst(Instruction):
    """ Equal instruction.
        op = 0xBA
        User Status Flags: no change.
    """
    name = 'SRC_EQ'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        return d_a == const4

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_LT_Inst(Instruction):
    """ Less Than instruction.
        op = 0xFA
        User Status Flags: no change.
    """
    name = 'SRC_LT'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        return d_a < const4

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_MOV_Inst(Instruction):
    """ Move instruction.
        op = 0x82
        User Status Flags: no change.
    """
    name = 'SRC_MOV'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def fetch_operands(self):
        return [self.get_const4()]

    def compute_result(self, *args):
        const4 = args[0]
        return const4

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_MOV_A_Inst(Instruction):
    """ Move Value to Address Register instruction.
        op = 0xA0
        User Status Flags: no change.
    """
    name = 'SRC_MOV.A'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32)

    def fetch_operands(self):
        return [self.get_const4()]

    def compute_result(self, *args):
        const4 = args[0]
        return const4

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_SH_Inst(Instruction):
    """ Shift instruction.
        op = 0x06
        user Status Flags: no change.
    """
    name = 'SRC_SH'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_const4(self):
        return self.data['const4']

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        cond_const4_pos = (const4 & 0x8 == 0)  # const4 is positive
        result_1 = (d_a << const4) & extend_to_32_bits(cond_const4_pos)

        result_2 = 0
        if not const4 == 0:  # const4=0
            cond_const4_neg = extend_to_6_bits(cond_const4_pos) ^ 0x3f
            shift_count = twos_comp(const4, 4)    # if const4<0
            if shift_count < 0:
                shift_count = shift_count * (-1)
            cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
            mask_2 = (((1 << shift_count) - 1) << (32 - shift_count)) & cond_mask_2
            result_2 = (mask_2 | (d_a >> shift_count)) & extend_to_32_bits(cond_const4_neg)

        # final result & flags
        result = result_1 | result_2

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRC_SHA_Inst(Instruction):
    """ Arithmetic Shift instruction.
        op = 0x86
    """
    name = 'SRC_SHA'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def get_const4(self):
        return self.data['const4']

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        cond_const4_pos = (const4 & 0x8 == 0)  # const4 is positive
        result_1 = (d_a << const4) & extend_to_32_bits(cond_const4_pos)
        # compute carry out
        lower_limit = (32 - const4) & extend_to_6_bits(cond_const4_pos)
        if lower_limit == 32:  # const4=0
            carry_out_1_mask = 0
        else:
            carry_out_1_mask = (((1 << 32) - 1) >> (31 - lower_limit)) << (31 - lower_limit)
        cond_carry_out_1 = ((const4 & 0xf) == 0xf) & cond_const4_pos  # if const4[4:0]
        carry_out_1 = carry(d_a, carry_out_1_mask, 0) & extend_to_32_bits(cond_carry_out_1)

        result_2 = 0
        carry_out_2 = 0
        if not const4 == 0:  # const4=0
            cond_const4_neg = extend_to_6_bits(cond_const4_pos) ^ 0x3f
            shift_count = twos_comp(const4, 4)    # if const4<0
            if shift_count < 0:
                shift_count = shift_count * (-1)
            cond_mask_2 = extend_bits((d_a & 0x80000000 != 0), shift_count)     # D[a][31] is set
            mask_2 = (((1 << shift_count) - 1) << (32 - shift_count)) & cond_mask_2
            result_2 = (mask_2 | (d_a >> shift_count)) & extend_to_32_bits(cond_const4_neg)
            # compute carry out
            carry_out_2_mask = (1 << (shift_count-1)) - 1
            carry_out_2 = carry(d_a, carry_out_2_mask, 0) & (cond_const4_pos ^ 1)

        # result & flags
        result = result_1 | result_2
        c = carry_out_1 | carry_out_2
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
