#!/usr/bin/env python3
""" brc_instr.py
Implementation of BRC format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class BRC_Jump_Instructions_df(Instruction):
    """ Jump if Equal instruction:
            op = 0xDF
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal instruction:
            op = 0xDF
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRC_Jump_Instructions_df ...'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:]
        const4 = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "const4": int(const4.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRC_JEQ'
        elif op2 == 1:
            self.name = 'BRC_JNE'
        else:
            self.name = "Unknown"

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_pc(), self.get_const4(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        pc = args[1]
        const4 = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRC_JEQ
            cond = d_a.signed == const4

        elif self.data['op2'] == 1:  # BRC_JNE
            cond = d_a.signed != const4

        else:
            print("Error: Unknown op2 '{0}'!".format(self.data['op2']))
            print("BRC instruction OP=DF, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRC_Jump_Instructions_ff(Instruction):
    """ Jump if Greater Than or Equal instruction.
            op = 0xFF
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Greater Than or Equal Unsigned instruction.
            op = 0xFF
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRC_Jump_Instructions_ff ...'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:]
        const4 = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = tmp[:1]
        data = {"a": int(a.bin, 2),
                "const4": int(const4.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": int(op2.bin, 2)}

        if op2 == 0:
            self.name = 'BRC_JGE'
        elif op2 == 1:
            self.name = 'BRC_JGE.U'
        else:
            self.name = "Unknown"

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_pc(), self.get_const4(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        pc = args[1]
        const4 = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRC_JGE
            cond = d_a.signed >= const4

        elif self.data['op2'] == 1:  # BRC_JGE.U
            cond = d_a >= const4  # unsigned comparison

        else:
            print("Error: Unknown op2 '{0}'!".format(self.data['op2']))
            print("BRC instruction OP=FF, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRC_Jump_Instructions_bf(Instruction):
    """ Jump if Less Than instruction.
            op = 0xBF
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Less Than Unsigned instruction.
            op = 0xBF
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRC Jump Instructions OP=BF ...'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:]
        const4 = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "const4": int(const4.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRC_JLT'
        elif op2 == 1:
            self.name = 'BRC_JLT.U'
        else:
            self.name = "Unknown"

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_pc(), self.get_const4(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        pc = args[1]
        const4 = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRC_JLT
            cond = d_a.signed < const4

        elif self.data['op2'] == 1:  # BRC_JLT.U
            cond = d_a < const4  # unsigned comparison

        else:
            print("Error: Unknown op2 '{0}'!".format(self.data['op2']))
            print("BRC instruction OP=BF, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRC_Jump_Instructions_9f(Instruction):
    """ Jump if Not Equal and Increment instruction.
            op = 0x9F
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal and Decrement instruction.
            op = 0x9F
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRC Jump Instructions OP=9F ...'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:]
        const4 = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "const4": int(const4.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRC_JNEI'
        elif op2 == 1:
            self.name = 'BRC_JNED'
        else:
            self.name = "Unknown"

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_4).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_pc(), self.get_const4(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        pc = args[1]
        const4 = args[2]
        disp15 = args[3]
        cond = d_a.signed != const4
        if self.data['op2'] == 0:  # BRC_JNEI
            self.put(d_a + 1, "d{0}".format(self.data['a']))

        elif self.data['op2'] == 1:  # BRC_JNED
            self.put(d_a - 1, "d{0}".format(self.data['a']))

        else:
            print("Error: Unknown op2 '{0}'!".format(self.data['op2']))
            print("BRC instruction OP=9F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)
