#!/usr/bin/env python3
""" sc_instr.py
Implementation of SC format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SC_AND_Inst(Instruction):
    """ Bitwise AND instruction.
        op = 0x16
        User Status Flags: no change.
    """
    name = 'SC_AND'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const8(self):
        return self.constant(self.data['a'], Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_const8()

    def compute_result(self, *args):
        d_15 = args[0]
        const8 = args[1]
        return d_15 & const8

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_LD_A_Inst(Instruction):
    """ Load Word from Address Register instruction.
        op = 0xD8
        User Status Flags: no change.
    """
    name = 'SC_LD.A'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "a15"

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_8).cast_to(Type.int_32)

    def get_a_10(self):
        return self.get("a10", Type.int_32)

    def fetch_operands(self):
        return self.get_a_10(), self.get_const8()

    def compute_result(self, *args):
        a_10 = args[0]
        const8 = args[1]
        addr = a_10 + (const8 << 2)
        return self.load(addr, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_LD_W_Inst(Instruction):
    """ Load Word instruction.
        op = 0x58
        User Status Flags: no change.
    """
    name = 'SC_LD.W'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_8).cast_to(Type.int_32)

    def get_a_10(self):
        return self.get("a10", Type.int_32)

    def fetch_operands(self):
        return self.get_a_10(), self.get_const8()

    def compute_result(self, *args):
        a_10 = args[0]
        const8 = args[1]
        addr = a_10 + (const8 << 2)
        return self.load(addr, Type.int_32)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_MOV_Inst(Instruction):
    """ MOV instruction.
        op = 0xDA
        User Status Flags: no change.
    """
    name = 'SC_MOV'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(0xa)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const8()]

    def compute_result(self, *args):
        const8 = args[0]
        return const8

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_OR_Inst(Instruction):
    """ Bitwise OR instruction.
        op = 0x96
        User Status Flags: no change.
    """
    name = 'SC_OR'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "d15"

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_8).cast_to(Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_const8()

    def compute_result(self, *args):
        d_15 = args[0]
        const8 = args[1]
        return d_15 | const8

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_SUB_A_Inst(Instruction):
    """ Subtract Address instruction.
        op = 0x20
        User Status Flags: no change.
    """
    name = 'SC_SUB.A'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    @staticmethod
    def get_dst_reg():
        return "a10"

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_32)

    def get_a_10(self):
        return self.get("a10", Type.int_32)

    def fetch_operands(self):
        return self.get_a_10(), self.get_const8()

    def compute_result(self, *args):
        a_10 = args[0]
        const8 = args[1]
        return a_10 - const8

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SC_ST_A_Inst(Instruction):
    """ Store Word from Address Register instruction.
        op = 0xF8
        User Status Flags: no change.
    """
    name = 'SC_ST.A'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_8).cast_to(Type.int_32)

    def get_a_10(self):
        return self.get("a10", Type.int_32)

    def get_A_15(self):
        return self.get("a15", Type.int_32)

    def fetch_operands(self):
        return self.get_A_15(), self.get_a_10(), self.get_const8()

    def compute_result(self, *args):
        A_15 = args[0]
        a_10 = args[1]
        const8 = args[2]
        addr = a_10 + (const8 << 2)
        self.store(A_15, addr)

class SC_ST_W_Inst(Instruction):
    """ Store Word instruction.
        op = 0x78
        User Status Flags: no change.
    """
    name = 'SC_ST.W'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(8)[2:].zfill(4))
    bin_format = op + 'a'*8

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"const8": int(data['a'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_const8(self):
        return self.constant(self.data['const8'], Type.int_8).cast_to(Type.int_32)

    def get_a_10(self):
        return self.get("a10", Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_a_10(), self.get_const8()

    def compute_result(self, *args):
        d_15 = args[0]
        a_10 = args[1]
        const8 = args[2]
        addr = a_10 + (const8 << 2)
        self.store(d_15, addr)
