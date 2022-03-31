#!/usr/bin/env python3
""" slr_instr.py
Implementation of SLR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SLR_LD_A_D4_Inst(Instruction):
    """ Load Word to Address Register instruction.
        op = 0xD4
        User Status Flags: no change.
    """
    name = 'SLR_LD.A_D4'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return self.load(a_b, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_A_C4_Inst(Instruction):
    """ Load Word to Address Register instruction (Post-increment Addressing Mode).
        op = 0xC4
        User Status Flags: no change.
    """
    name = 'SLR_LD.A_C4'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        result = self.load(a_b, Type.int_32)
        self.put(a_b + 4, "a{0}".format(self.data['b']))  # post increment
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_BU_14_Inst(Instruction):
    """ Load Byte Unsigned instruction.
        op = 0x14
        User Status Flags: no change.
    """
    name = 'SLR_LD.BU_14'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return self.load(a_b, Type.int_8)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_BU_04_Inst(Instruction):
    """ Load Byte Unsigned instruction (Post-increment Addressing Mode).
        op = 0x04
        User Status Flags: no change.
    """
    name = 'SLR_LD.BU_04'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        result = self.load(a_b, Type.int_8)
        self.put(a_b + 1, "a{0}".format(self.data['b']))  # post increment
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_H_94_Inst(Instruction):
    """ Load Half-word instruction.
        op = 0x94
        User Status Flags: no change.
    """
    name = 'SLR_LD.H_94'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return self.load(a_b, Type.int_16).cast_to(Type.int_32, signed=True)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_H_84_Inst(Instruction):
    """ Load Half-word instruction (Post-increment Addressing Mode).
        op = 0x84
        User Status Flags: no change.
    """
    name = 'SLR_LD.H_84'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        result = self.load(a_b, Type.int_16).cast_to(Type.int_32, signed=True)
        self.put(a_b + 2, "a{0}".format(self.data['b']))  # post increment
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_W_54_Inst(Instruction):
    """ Load Word instruction.
        op = 0x54
        User Status Flags: no change.
    """
    name = 'SLR_LD.W_54'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        return self.load(a_b, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SLR_LD_W_44_Inst(Instruction):
    """ Load Word instruction (Post-increment Addressing Mode).
        op = 0x44
        User Status Flags: no change.
    """
    name = 'SLR_LD.W_44'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'c'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"b": int(data['b'], 2),
                "c": int(data['c'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data["c"])

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b()]

    def compute_result(self, *args):
        a_b = args[0]
        result = self.load(a_b, Type.int_32)
        self.put(a_b + 4, "a{0}".format(self.data['b']))  # post increment
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
