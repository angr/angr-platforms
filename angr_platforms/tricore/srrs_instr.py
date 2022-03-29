#!/usr/bin/env python3
""" srrs_instr.py
Implementation of SRRS format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SRRS_ADDSC_A_Inst(Instruction):
    """ Add Scaled Index to Address instruction.
        op = 0x10
        User Status Flags: no change.
    """
    name = 'SRRS_ADDSC.A'
    op = "{0}".format(bin(16)[2:].zfill(6))
    bin_format = 'n'*2 + op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2),
                "n": int(data['n'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_n(self):
        return self.data['n']

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_a_b(), self.get_n()

    def compute_result(self, *args):
        d_15 = args[0]
        a_b = args[1]
        n = args[2]
        return a_b + (d_15 << n)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
