#!/usr/bin/env python3
""" bol_instr.py
Implementation of BOL format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class BOL_LD_A(Instruction):
    """ Load Word to Address Register instruction.
        op = 0x99
        User Status Flags: no change.
    """
    name = 'BOL_LD.A'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off16 = bitstring.BitArray(bin="{0}{1}{2}".format(tmp[4:10].bin,
                                                          tmp[0:4].bin,
                                                          tmp[10:16].bin))
        a = tmp[20:]
        b = tmp[16:20]
        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off16": int(off16.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_offset(self):
        return self.constant(self.data['off16'], Type.int_16).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        ea = a_b + offset
        result = self.load(ea, Type.int_32)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BOL_LEA(Instruction):
    """ Load Effective Address instruction.
        op = 0xD9
        User Status Flags: no change.
    """
    name = 'BOL_LEA'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off16 = bitstring.BitArray(bin="{0}{1}{2}".format(tmp[4:10].bin,
                                                          tmp[0:4].bin,
                                                          tmp[10:16].bin))
        a = tmp[20:]
        b = tmp[16:20]
        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off16": int(off16.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_offset(self):
        return self.constant(self.data['off16'], Type.int_16).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        ea = a_b + offset
        return ea

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BOL_LD_W(Instruction):
    """ Load Word instruction.
        op = 0x19
        User Status Flags: no change.
    """
    name = 'BOL_LD.W'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off16 = bitstring.BitArray(bin="{0}{1}{2}".format(tmp[4:10].bin,
                                                          tmp[0:4].bin,
                                                          tmp[10:16].bin))
        a = tmp[20:]
        b = tmp[16:20]
        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off16": int(off16.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_offset(self):
        return self.constant(self.data['off16'], Type.int_16).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_b(), self.get_offset()]

    def compute_result(self, *args):
        a_b = args[0]
        offset = args[1]
        addr = a_b + offset
        result = self.load(addr, Type.int_32)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BOL_ST_W(Instruction):
    """ Store Word instruction.
        op = 0x59
        User Status Flags: no change.
    """
    name = 'BOL_ST.W'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(9)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off16 = bitstring.BitArray(bin="{0}{1}{2}".format(tmp[4:10].bin,
                                                          tmp[0:4].bin,
                                                          tmp[10:16].bin))
        a = tmp[20:]
        b = tmp[16:20]
        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "off16": int(off16.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_offset(self):
        return self.constant(self.data['off16'], Type.int_16).cast_to(Type.int_32, signed=True)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b(), self.get_offset()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        offset = args[2]
        ea = a_b + offset
        self.store(d_a, ea)
