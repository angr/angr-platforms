#!/usr/bin/env python3
""" rrrr_instr.py
Implementation of RRRR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import extend_to_32_bits, sign_extend_3
from .logger import log_this


class RRRR_DEXTR_Inst(Instruction):
    """ Insert Bit Field instruction.
        op = 0x17
        op2 = 0x04 (3 bits)
        User Status Flags: no change.
    """
    name = 'RRRR_DEXTR'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(4)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*5 + 'c'*4 + 'd'*4

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
        pos = d_d & 0x1f
        pos = pos.cast_to(Type.int_8)
        mask = ((1 << pos)-1).cast_to(Type.int_32)
        tmp_1 = d_a << pos
        tmp_2 = (d_b & (mask << (32 - pos))) >> (32 - pos)
        result = tmp_1 | tmp_2
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRRR_EXTR_Inst(Instruction):
    """ Extract Bit Field instruction.
        op = 0x17
        op2 = 0x02 (3 bits)
        User Status Flags: no change.
    """
    name = 'RRRR_EXTR'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(2)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*5 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_d_1(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d_1(), self.get_d_d_2()

    def compute_result(self, *args):
        d_a = args[0]
        d_d_1 = args[1]
        d_d_2 = args[2]
        pos = (d_d_1 & 0x1f).cast_to(Type.int_8)    # E[d] & 0x1f
        width = (d_d_2 & 0x1f).cast_to(Type.int_8)  # E[d+1] & 0x1f

        tmp = self.constant(0xffffffff, Type.int_32)
        mask = ((1 << width) - 1).cast_to(Type.int_32)
        result_tmp = (d_a >> pos) & mask
        result = sign_extend_3(result_tmp, width, tmp)

        # undefined result if (pos+width)>32 or width=0
        cond_undefined = extend_to_32_bits(((pos + width).cast_to(Type.int_32) >> 5) == 0)
        result = result & cond_undefined

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRRR_EXTR_U_Inst(Instruction):
    """ Extract Bit Field Unsigned instruction.
        op = 0x17
        op2 = 0x03 (3 bits)
        User Status Flags: no change.
    """
    name = 'RRRR_EXTR.U'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(3)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*5 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "c": int(data['c'], 2),
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_d_1(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d_1(), self.get_d_d_2()

    def compute_result(self, *args):
        d_a = args[0]
        d_d_1 = args[1]
        d_d_2 = args[2]
        pos = (d_d_1 & 0x1f).cast_to(Type.int_8)    # E[d] & 0x1f
        width = (d_d_2 & 0x1f).cast_to(Type.int_8)  # E[d+1] & 0x1f

        mask = ((1 << width) - 1).cast_to(Type.int_32)
        result = (d_a >> pos) & mask

        # undefined result if (pos+width)>32 or width=0
        cond_undefined = extend_to_32_bits(((pos + width).cast_to(Type.int_32) >> 5) == 0)
        result = result & cond_undefined

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RRRR_INSERT_Inst(Instruction):
    """ Insert Bit Field instruction.
        op = 0x17
        op2 = 0x00
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RRRR_INSERT'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'i'*5 + 'c'*4 + 'd'*4

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

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        # E[d]
        pos = self.get("d{0}".format(self.data['d']), Type.int_8)
        width = self.get("d{0}".format(self.data['d']+1), Type.int_8)

        const_1 = self.constant(1, Type.int_32)
        mask = ((const_1 << width)-1) << pos
        result = (d_a & ~mask) | ((d_b << pos) & mask)

        # undefined result if (pos + width) > 32
        cond_undefined = extend_to_32_bits(((pos + width) >> 5) == 0)
        result = result & cond_undefined.cast_to(Type.int_32)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
