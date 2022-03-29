#!/usr/bin/env python3
""" ssr_instr.py
Implementation of SSR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SSR_ST_A_Inst(Instruction):
    """ Store Word from Address Register instruction.
        op = 0xF4
        User Status Flags: no change.
    """
    name = 'SSR_ST.A'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        self.store(a_a, a_b)

class SSR_ST_A_E4_Inst(Instruction):
    """ Store Word from Address Register instruction (Post-increment Addressing mode).
        op = 0xE4
        User Status Flags: no change.
    """
    name = 'SSR_ST.A_E4'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        self.store(a_a, a_b)
        self.put(a_b+4, "a{0}".format(self.data['b']))

class SSR_ST_B_Inst(Instruction):
    """ Store Byte instruction.
        op = 0x34
        User Status Flags: no change.
    """
    name = 'SSR_ST.B'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        val = d_a.cast_to(Type.int_8)
        self.store(val, a_b)

class SSR_ST_B_24_Inst(Instruction):
    """ Store Byte instruction (Post-increment Addressing Mode).
        op = 0x24
        User Status Flags: no change.
    """
    name = 'SSR_ST.B_24'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        val = d_a & 0xff
        self.store(val, a_b)
        self.put(a_b+1, "a{0}".format(self.data['b']))

class SSR_ST_H_Inst(Instruction):
    """ Store Half-word instruction.
        op = 0xB4
        User Status Flags: no change.
    """
    name = 'SSR_ST.H'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        val = d_a & 0xffff
        self.store(val, a_b)

class SSR_ST_H_A4_Inst(Instruction):
    """ Store Half-word instruction (Post-increment Addressing Mode).
        op = 0xA4
        User Status Flags: no change.
    """
    name = 'SSR_ST.H_A4'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        val = d_a & 0xffff
        self.store(val, a_b)
        self.put(a_b+2, "a{0}".format(self.data['b']))

class SSR_ST_W_Inst(Instruction):
    """ Store Word instruction.
        op = 0x74
        User Status Flags: no change.
    """
    name = 'SSR_ST.W'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        self.store(d_a, a_b)

class SSR_ST_W_64_Inst(Instruction):
    """ Store Word instruction (Post-increment Addressing Mode).
        op = 0x64
        User Status Flags: no change.
    """
    name = 'SSR_ST.W_64'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_a_b()

    def compute_result(self, *args):
        d_a = args[0]
        a_b = args[1]
        self.store(d_a, a_b)
        self.put(a_b+4, "a{0}".format(self.data['b']))
