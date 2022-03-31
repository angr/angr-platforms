#!/usr/bin/env python3
""" sbrn_instr.py
Implementation of SBRN format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SBRN_JZ_T_Inst(Instruction):
    """ Jump if Zero Bit instruction.
        op = 0x2E
        User Status Flags: no change.
    """
    name = 'SBRN_JZ.T'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "n": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_n(self):
        return self.data['n']

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_disp4(), self.get_n()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        disp4 = args[2]
        n = args[3]
        cond = d_15[n] == 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBRN_JNZ_T_Inst(Instruction):
    """ Jump if Not Equal to Zero Bit instruction.
        op = 0xAE
        User Status Flags: no change.
    """
    name = 'SBRN_JNZ.T'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "n": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_n(self):
        return self.data['n']

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_disp4(), self.get_n()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        disp4 = args[2]
        n = args[3]
        cond = d_15[n] == 1
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)
