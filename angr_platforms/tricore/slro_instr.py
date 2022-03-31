#!/usr/bin/env python3
""" slro_instr.py
Implementation of SLRO format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SLRO_LD_A_Inst(Instruction):
    """ Load Word to Address Register instruction.
        op = 0xC8
        User Status Flags: no change.
    """
    name = 'SLRO_LD.A'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data["c"])

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        a_15 = args[0]
        offset = args[1]
        return self.load(a_15 + (offset << 2), Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLRO_LD_BU_Inst(Instruction):
    """ Load Byte Unsigned instruction.
        op = 0x08
        User Status Flags: no change.
    """
    name = 'SLRO_LD.BU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        a_15 = args[0]
        offset = args[1]
        return self.load(a_15 + offset, Type.int_8).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLRO_LD_H_Inst(Instruction):
    """ Load Half-word instruction.
        op = 0x88
        User Status Flags: no change.
    """
    name = 'SLRO_LD.H'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        a_15 = args[0]
        offset = args[1]
        return self.load(a_15 + (offset << 1), Type.int_16).cast_to(Type.int_32, signed=True)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLRO_LD_W_Inst(Instruction):
    """ Load Word Unsigned instruction.
        op = 0x48
        User Status Flags: no change.
    """
    name = 'SLRO_LD.W'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        a_15 = args[0]
        offset = args[1]
        return self.load(a_15 + (offset << 2), Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
