#!/usr/bin/env python3
""" ssro_instr.py
Implementation of SSRO format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SSRO_ST_A_Inst(Instruction):
    """ Store Word from Address Register instruction.
        op = 0xE8
        User Status Flags: no change.
    """
    name = 'SSRO_ST.A'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "off4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        a_a = args[0]
        a_15 = args[1]
        offset = args[2]
        addr = a_15 + (offset << 2)
        self.store(a_a, addr)

class SSRO_ST_B_Inst(Instruction):
    """ Store Byte instruction.
        op = 0x28
        User Status Flags: no change.
    """
    name = 'SSRO_ST.B'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "off4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        d_a = args[0]
        a_15 = args[1]
        offset = args[2]
        val = d_a & 0xff
        addr = a_15 + offset
        self.store(val, addr)

class SSRO_ST_H_Inst(Instruction):
    """ Store Half-word instruction.
        op = 0xA8
        User Status Flags: no change.
    """
    name = 'SSRO_ST.H'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "off4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        d_a = args[0]
        a_15 = args[1]
        offset = args[2]
        val = d_a & 0xffff
        addr = a_15 + (offset << 1)
        self.store(val, addr)

class SSRO_ST_W_Inst(Instruction):
    """ Store Word instruction.
        op = 0x68
        User Status Flags: no change.
    """
    name = 'SSRO_ST.W'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "off4": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_15(), self.get_offset()

    def compute_result(self, *args):
        d_a = args[0]
        a_15 = args[1]
        offset = args[2]
        addr = a_15 + (offset << 2)
        self.store(d_a, addr)
