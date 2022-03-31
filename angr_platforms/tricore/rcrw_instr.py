#!/usr/bin/env python3
""" rcrw_instr.py
Implementation of RCRW format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .rtl import extend_to_32_bits
from .logger import log_this


class RCRW_INSERT(Instruction):
    """ Insert Bit Field instruction:
        op = 0xD7
        op2 = 0x00  (3-bit)
        User Status Flags: no change.
    """
    name = 'RCRW_INSERT'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'w'*5 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        width = int(data['w'], 2)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2),
                "c": int(data['c'], 2),
                "w": width,
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_d = args[1]
        const4 = args[2]
        pos = (d_d & 0x1f).cast_to(Type.int_8)
        width = self.data['w']

        const_1 = self.constant(1, Type.int_32)
        mask = ((const_1 << width)-1) << pos
        result = (d_a & ~mask) | ((const4 << pos) & mask)

        # undefined result if (pos + width) > 32
        cond_undefined = extend_to_32_bits(((pos + width) >> 5) == 0)
        result = result & cond_undefined.cast_to(Type.int_32)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RCRW_IMASK(Instruction):
    """ Insert Mask instruction:
        op = 0xD7
        op2 = 0x01  (3-bit)
        User Status Flags: no change.
    """
    name = 'RCRW_IMASK'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(1)[2:].zfill(3))
    bin_format = op + 'b'*4 + 'a'*4 + op2 + 'w'*5 + 'c'*4 + 'd'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        width = int(data['w'], 2)
        data = {"const4": int(data['b'], 2),
                "c": int(data['c'], 2),
                "w": width,
                "d": int(data['d'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_32)

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_d(), self.get_const4()

    def compute_result(self, *args):
        d_d = args[0]
        const4 = args[1]
        pos = (d_d & 0x1f).cast_to(Type.int_8)
        width = self.data['w']

        const_1 = self.constant(1, Type.int_32)
        result_1 = ((const_1 << width)-1) << pos
        result_2 = const4 << pos

        # undefined result if (pos + width) > 32
        cond_undefined = extend_to_32_bits(((pos + width) >> 5) == 0)
        result_1 = result_1 & cond_undefined.cast_to(Type.int_32)
        result_2 = result_2 & cond_undefined.cast_to(Type.int_32)

        self.put(result_1, "d{0}".format(self.data['c']+1))
        self.put(result_2, "d{0}".format(self.data['c']))
