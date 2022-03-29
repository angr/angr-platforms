#!/usr/bin/env python3
""" sbc_instr.py
Implementation of SBC format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SBC_JEQ_Inst(Instruction):
    """ Jump if Equal instruction.
        op = 0x1E
        User Status Flags: no change.
    """
    name = 'SBC_JEQ'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const4": int(data['b'], 2),
                "disp4": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_const4(), self.get_disp4()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        const4 = args[2]
        disp4 = args[3]
        cond = d_15 == const4
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBC_JNE_Inst(Instruction):
    """ Jump if Not Equal instruction.
        op = 0x5E
        User Status Flags: no change.
    """
    name = 'SBC_JNE'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "const4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_pc(), self.get_const4(), self.get_disp4()

    def compute_result(self, *args):
        d_15 = args[0]
        pc = args[1]
        const4 = args[2]
        disp4 = args[3]
        cond = d_15.signed != const4
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)
