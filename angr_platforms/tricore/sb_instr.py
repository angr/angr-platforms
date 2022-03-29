#!/usr/bin/env python3
""" sb_instr.py
Implementation of SB format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SB_J_Inst(Instruction):
    """ Jump Unconditional instruction.
        op = 0x3C
        User Status Flags: no change.
    """
    name = 'SB_J'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp8(self):
        return self.constant(self.data['disp8'], Type.int_8).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return self.get_pc(), self.get_disp8()

    def compute_result(self, *args):
        pc = args[0]
        disp8 = args[1]
        dest = pc + (disp8 << 1)
        self.jump(None, dest)

class SB_JNZ_Inst(Instruction):
    """ Jump if Not Equal to Zero instruction.
        op = 0xEE
        User Status Flags: no change.
    """
    name = 'SB_JNZ'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp8": int(data['a'],2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp8(self):
        return self.constant(self.data['disp8'], Type.int_8).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_disp8()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        disp8 = args[2]
        cond = d_15 != 0
        dest = pc + (disp8 << 1)
        self.jump(cond, dest)

class SB_JZ_Inst(Instruction):
    """ Jump if Zero instruction.
        op = 0x6E
        User Status Flags: no change.
    """
    name = 'SB_JZ'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp8(self):
        return self.constant(self.data['disp8'], Type.int_8).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_disp8()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        disp8 = args[2]
        cond = d_15 == 0
        dest = pc + (disp8 << 1)
        self.jump(cond, dest)
