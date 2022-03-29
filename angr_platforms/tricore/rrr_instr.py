#!/usr/bin/env python3
""" rrr_instr.py
Implementation of RRR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RRR_CADD_Inst(Instruction):
    """ Conditional Add instruction.
        op = 0x2B
        op2 = 0x00
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR_CADD'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = extend_to_32_bits(d_d != 0)
        result = ((d_a + d_b) & condition) | (d_a & ~condition)

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

class RRR_CADDN_Inst(Instruction):
    """ Conditional Add-Not instruction.
        op = 0x2B
        op2 = 0x01 (4-bits)
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR_CADDN'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(1)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = extend_to_32_bits(d_d == 0)
        result = ((d_a + d_b) & condition) | (d_a & ~condition)

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

class RRR_CSUB_Inst(Instruction):
    """ Conditional Subtract instruction.
        op = 0x2B
        op2 = 0x02
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR_CSUB'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(2)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = extend_to_32_bits(d_d != 0)
        result = ((d_a - d_b) & condition) | (d_a & ~condition)

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

class RRR_CSUBN_Inst(Instruction):
    """ Conditional Subtract-Not instruction.
        op = 0x2B
        op2 = 0x03
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRR_CSUBN'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = extend_to_32_bits(d_d == 0)
        result = ((d_a - d_b) & condition) | (d_a & ~condition)

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

class RRR_DVADJ_Inst(Instruction):
    """ Divide-Adjust instruction:
        op = 0x6B
        op2 = 0x0D (4-bits)
        User Status Flags: no change.
    """
    name = 'RRR_DVADJ'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(0xd)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + '00' + 'i'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_d_d(), self.get_d_d_2()

    def compute_result(self, *args):
        d_b = args[0]
        d_d = args[1]
        d_d_2 = args[2]
        result = ((d_d_2 == d_b) and (d_d_2[31])).ite(
            (d_d[31]).ite(d_d.cast_to(Type.int_64),
                          (d_d+1).cast_to(Type.int_64)),
            (d_d[31]).ite(((d_d_2).cast_to(Type.int_64)<<32)|(d_d+1).cast_to(Type.int_64),
                          ((d_d_2).cast_to(Type.int_64)<<32) | d_d.cast_to(Type.int_64))
            )
        self.put(result & 0xffffffff, "d{0}".format(self.data['c']))
        self.put(result >> 32, "d{0}".format(self.data['c']+1))

class RRR_DVSTEP_Inst(Instruction):
    """ Divide-Step instruction:
        op = 0x6B
        op2 = 0x0F (4-bits)
        User Status Flags: no change.
    """
    name = 'RRR_DVSTEP'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(0xf)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + '00' + 'i'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_d_d(), self.get_d_d_2()

    def compute_result(self, *args):
        d_b = args[0]
        d_d = args[1]
        d_d_2 = args[2]
        dividend_sign = d_d_2[31]  # E[d][63]
        divisor_sign = d_b[31]
        quotient_sign = dividend_sign != divisor_sign
        addend = (quotient_sign).ite(d_b, 0-d_b)
        dividend_quotient = d_d  # E[d][31:0]
        remainder = d_d_2        # E[d][63:32]
        # iter 0
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 1
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 2
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 3
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 4
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 5
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 6
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)
        # iter 7
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = remainder + addend
        remainder = ((temp.signed < 0) == dividend_sign) .ite(temp, remainder)
        dividend_quotient = dividend_quotient | ((temp.signed < 0) == dividend_sign).ite(quotient_sign^1, quotient_sign)

        # put result into E[c]
        self.put(dividend_quotient & 0xffffffff, "d{0}".format(self.data['c']))
        self.put(remainder & 0xffffffff, "d{0}".format(self.data['c']+1))

class RRR_DVSTEP_U_Inst(Instruction):
    """ Divide-Step Unsigned instruction:
        op = 0x6B
        op2 = 0x0E (4-bits)
        User Status Flags: no change.
    """
    name = 'RRR_DVSTEP.U'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + '00' + 'i'*2 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_d_d(), self.get_d_d_2()

    def compute_result(self, *args):
        d_b = args[0]
        d_d = args[1]
        d_d_2 = args[2]
        divisor = d_b
        dividend_quotient = d_d  # E[d][31:0]
        remainder = d_d_2        # E[d][63:32]
        # iter 0
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 1
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 2
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 3
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 4
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 5
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 6
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)
        # iter 7
        remainder = (remainder << 1) | dividend_quotient[31]
        dividend_quotient <<= 1
        temp = (remainder & 0xffffffff) - divisor
        remainder = (temp.signed < 0).ite(remainder, temp)
        dividend_quotient = dividend_quotient | ((temp.signed < 0)^1)

        # put result into E[c]
        self.put(dividend_quotient & 0xffffffff, "d{0}".format(self.data['c']))
        self.put(remainder & 0xffffffff, "d{0}".format(self.data['c']+1))

class RRR_SEL_Inst(Instruction):
    """ Select instruction.
        op = 0x2B
        op2 = 0x04 (4-bits)
        User Status Flags: no change.
    """
    name = 'RRR_SEL'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = d_d != 0
        return self.ite(condition, d_a, d_b)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRR_SELN_Inst(Instruction):
    """ Select-Not instruction.
        op = 0x2B
        op2 = 0x05 (4-bits)
        User Status Flags: no change.
    """
    name = 'RRR_SELN'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    op2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*4 + 'c'*4 + 'd'*4

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
        condition = d_d == 0
        return self.ite(condition, d_a, d_b)

    def put(self, val, reg):
        offset = self._lookup_register(self.irsb_c.irsb.arch, reg)
        self.irsb_c.put(val, offset)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
