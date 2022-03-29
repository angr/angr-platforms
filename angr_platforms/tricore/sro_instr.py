#!/usr/bin/env python3
""" sro_instr.py
Implementation of SRO format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SRO_LD_A_Inst(Instruction):
    """ Load Word to Address Register instruction.
        op = 0xCC
        User Status Flags: no change.
    """
    name = 'SRO_LD.A'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "a15"

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        addr = a_b + (offset << 2)
        return self.load(addr, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRO_LD_BU_Inst(Instruction):
    """ Load Byte Unsigned instruction.
        op = 0x0C
        User Status Flags: no change.
    """
    name = 'SRO_LD.BU'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        addr = a_b + offset
        return self.load(addr, Type.int_8).cast_to(Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRO_LD_H_Inst(Instruction):
    """ Load Half-word instruction.
        op = 0x8C
        User Status Flags: no change.
    """
    name = 'SRO_LD.H'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        addr = a_b + (offset << 1)
        return self.load(addr, Type.int_16).cast_to(Type.int_32, signed=True)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRO_LD_W_Inst(Instruction):
    """ Load Word instruction.
        op = 0x4C
        User Status Flags: no change.
    """
    name = 'SRO_LD.W'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        addr = a_b + (offset << 2)
        return self.load(addr, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SRO_ST_A_Inst(Instruction):
    """ Store Word from Address Register instruction.
        op = 0xEC
        User Status Flags: no change.
    """
    name = 'SRO_ST.A'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_a_15(), self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        a_15 = args[0]
        a_b = args[1]
        offset = args[2]
        addr = a_b + (offset << 2)
        self.store(a_15, addr)

class SRO_ST_B_Inst(Instruction):
    """ Store Byte instruction.
        op = 0x2C
        User Status Flags: no change.
    """
    name = 'SRO_ST.B'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        d_15 = args[0]
        a_b = args[1]
        offset = args[2]
        addr = a_b + offset
        val = d_15 & 0xff
        self.store(val, addr)

class SRO_ST_H_Inst(Instruction):
    """ Load Half-word instruction.
        op = 0xAC
        User Status Flags: no change.
    """
    name = 'SRO_ST.H'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        d_15 = args[0]
        a_b = args[1]
        offset = args[2]
        addr = a_b + (offset << 1)
        val = d_15 & 0xffff
        self.store(val, addr)

class SRO_ST_W_Inst(Instruction):
    """ Load Word instruction.
        op = 0x6C
        User Status Flags: no change.
    """
    name = 'SRO_ST.W'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"off4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off4'], Type.int_4).cast_to(Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        d_15 = args[0]
        a_b = args[1]
        offset = args[2]
        addr = a_b + (offset << 2)
        self.store(d_15, addr)
