#!/usr/bin/env python3
""" rcpw_instr.py
Implementation of RCPW format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class RCPW_INSERT(Instruction):
    """ Insert Bit Field instruction.
        op = 0xB7
        op2 = 0x00  (2-bit)
        User Status Flags: no change.
    """
    name = 'RCPW_INSERT'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(2))
    bin_format = op + 'b'*4 + 'a'*4 + 'q'*1 + op2 +'w'*1 + 'w'*4 + 'c'*4 + 'p'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)

        width = int(data['w'], 2)
        pos = int("{0}{1}".format(data['p'],data['q']), 2)
        data = {"a": int(data['a'], 2),
                "const4": int(data['b'], 2),
                "c": int(data['c'], 2),
                "w": width,
                "p": pos}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        const4 = args[1]
        pos = self.data['p']
        width = self.data['w']
        if (pos + width > 32) or (width == 0):
            print("Error: Undefined result for (pos + width > 32)!")
            sys.exit(1)

        const_1 = self.constant(1, Type.int_32)
        mask = ((const_1 << width)-1) << pos
        result = (d_a & ~mask) | ((const4 << pos) & mask)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RCPW_IMASK(Instruction):
    """ Insert Mask instruction:
        op = 0xB7
        op2 = 0x01  (2-bit)
        User Status Flags: no change.
    """
    name = 'RCPW_IMASK'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(1)[2:].zfill(2))
    bin_format = op + 'b'*4 + 'a'*4 + 'q'*1 + op2 +'w'*1 + 'w'*4 + 'c'*4 + 'p'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)

        width = int(data['w'], 2)
        pos = int("{0}{1}".format(data['p'],data['q']), 2)

        data = {"const4": int(data['b'], 2),
                "c": int(data['c'], 2),
                "w": width,
                "p": pos}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const4()]

    def compute_result(self, *args):
        const4 = args[0]
        pos = self.data['p']
        width = self.data['w']
        if (pos + width > 32) or (width == 0):
            print("Error: Undefined result for (pos + width > 32)!")
            sys.exit(1)

        const_1 = self.constant(1, Type.int_32)
        result_1 = ((const_1 << width)-1) << pos
        result_2 = const4 << pos
        self.put(result_1, "d{0}".format(self.data['c']+1))
        self.put(result_2, "d{0}".format(self.data['c']))
