#!/usr/bin/env python3
""" brr_instr.py
Implementation of BRR format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class BRR_Jump_Instruczions_7F(Instruction):
    """ Jump if Greater Than or Equal instruction.
            op = 0x7F
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Greater Than or Equal Unsigned instruction.
            op = 0x7F
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump Instructions OP=7F ...'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xf)[2:].zfill(4))
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
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JGE'
        elif op2 == 1:
            self.name = 'BRR_JGE.U'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        pc = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRR_JGE
            cond = d_a.signed >= d_b

        elif self.data['op2'] == 1:  # BRR_JGE.U
            cond = d_a >= d_b  # Unsigned comparison

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=7F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRR_Jump_Instructions_3F(Instruction):
    """ Jump if Less Than instruction.
            op = 0x3F
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Less Than Unsigned instruction.
            op = 0x3F
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump Instructions OP=3F ...'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0xf)[2:].zfill(4))
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
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JLT'
        elif op2 == 1:
            self.name = 'BRR_JLT.U'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        pc = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRR_JLT
            cond = d_a.signed < d_b

        elif self.data['op2'] == 1:  # BRR_JLT.U
            cond = d_a < d_b  # Unsigned comparison

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=3F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRR_Jump_Instructions_5F(Instruction):
    """ Jump if Equal instruction:
            op = 0x5F
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal instruction:
            op = 0x5F
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump instructions OP=5F ...'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(0xf)[2:].zfill(4))
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
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JEQ'
        elif op2 == 1:
            self.name = 'BRR_JNE'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        pc = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRR_JEQ
            cond = d_a.signed == d_b

        elif self.data['op2'] == 1:  # BRR_JNE
            cond = d_a.signed != d_b

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=5F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRR_Jump_Instructions_7D(Instruction):
    """ Jump if Equal Address instruction.
            op = 0x7D
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal Address instruction.
            op = 0x7D
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump instructions OP=7D ...'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xd)[2:].zfill(4))
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
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JEQ.A'
        elif op2 == 1:
            self.name = 'BRR_JNE.A'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_a_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        a_a = args[0]
        a_b = args[1]
        pc = args[2]
        disp15 = args[3]
        if self.data['op2'] == 0:  # BRR_JEQ.A
            cond = a_a.signed == a_b

        elif self.data['op2'] == 1:  # BRR_JNE.A
            cond = a_a.signed != a_b

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=7D, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRR_Jump_Instructions_1F(Instruction):
    """ Jump if Not Equal and Increment instruction.
            op = 0x1F
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal and Decrement instruction.
            op = 0x1F
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump instructions OP=1F ...'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(0xf)[2:].zfill(4))
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
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JNEI'
        elif op2 == 1:
            self.name = 'BRR_JNED'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        pc = args[2]
        disp15 = args[3]
        condition = d_a.signed != d_b
        if self.data['op2'] == 0:  # BRR_JNEI
            self.put(d_a + 1, "d{0}".format(self.data['a']))

        elif self.data['op2'] == 1:  # BRR_JNED
            self.put(d_a - 1, "d{0}".format(self.data['a']))

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=1F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(condition, dest)

class BRR_Jump_Instructions_BD(Instruction):
    """ Jump if Zero Address instruction.
            op = 0xBD
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Jump if Not Equal to Zero Address instruction.
            op = 0xBD
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Jump instructions OP=BD ...'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0xd)[2:].zfill(4))
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
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"a": int(a.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_JZ.A'
        elif op2 == 1:
            self.name = 'BRR_JNZ.A'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        a_a = args[0]
        pc = args[1]
        disp15 = args[2]
        if self.data['op2'] == 0:  # BRR_JZ.A
            cond = a_a.signed == 0

        elif self.data['op2'] == 1:  # BRR_JNZ.A
            cond = a_a.signed != 0

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=BD, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)

class BRR_Loop_Instructions_FD(Instruction):
    """ Loop instruction.
            op = 0xFD
            op2 = 0x0  (1 bit)
            User Status Flags: no change.
        Loop Unconditional instruction.
            op = 0xFD
            op2 = 0x1  (1 bit)
            User Status Flags: no change.
    """
    name = 'BRR Loop instructions OP=FD ...'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        b = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)
        data = {"b": int(b.bin, 2),
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        if op2 == 0:
            self.name = 'BRR_LOOP'
        elif op2 == 1:
            self.name = 'BRR_LOOPU'
        else:
            self.name = 'Unknown'

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15']<<1, Type.int_15).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_pc(), self.get_disp15()

    def compute_result(self, *args):
        a_b = args[0]
        pc = args[1]
        disp15 = args[2]
        if self.data['op2'] == 0:  # LOOP
            cond = a_b.signed != 0
            self.put(a_b - 1, "a{0}".format(self.data['b']))

        elif self.data['op2'] == 1:  # LOOPU
            pass

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("BRR instruction OP=FD, OP2=Unknown")
            sys.exit(1)

        dest = pc + disp15
        self.jump(cond, dest)
