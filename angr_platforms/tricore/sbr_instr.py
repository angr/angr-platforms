#!/usr/bin/env python3
""" sbr_instr.py
Implementation of SBR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SBR_JEQ_Inst(Instruction):
    """ Jump if Equal instruction.
        op = 0x3E
        User Status Flags: no change.
    """
    name = 'SBR_JEQ'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_15 = args[0]
        d_b = args[1]
        pc = args[2]
        disp4 = args[3]
        cond = d_15 == d_b
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JGEZ_Inst(Instruction):
    """ Jump if Greater Than or Equal to Zero instruction.
        op = 0xCE
        User Status Flags: no change.
    """
    name = 'SBR_JGEZ'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b >= 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JGTZ_Inst(Instruction):
    """ Jump if Greater Than Zero instruction.
        op = 0x4E
        User Status Flags: no change.
    """
    name = 'SBR_JGTZ'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b > 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JLEZ_Inst(Instruction):
    """ Jump if Less Than or Equal to Zero instruction.
        op = 0x8E
        User Status Flags: no change.
        Note: Displacement should be even.
        The bits of a (in bin_format) should be:
            - flipped
            - moved one time to left
        to represent the always 0 bit.
    """
    name = 'SBR_JLEZ'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + '0' + 'a'*3

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        a = data['a'][-1:]+data['a'][:-1]  # flip bits order
        data = {"disp4": int(a, 2) << 1,
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b <= 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JLTZ_Inst(Instruction):
    """ Jump if Less Than Zero instruction.
        op = 0x0E
        User Status Flags: no change.
        Note: Displacement should be even.
        The bits of a (in bin_format) should be:
            - flipped
            - moved one time to left
        to represent the always 0 bit.
    """
    name = 'SBR_JLTZ'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + '0' + 'a'*3

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        a = data['a'][-1:]+data['a'][:-1]  # flip bits order
        data = {"disp4": int(a, 2) << 1,
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b < 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JNE_Inst(Instruction):
    """ Jump if Not Equal instruction.
        op = 0x7E
        User Status Flags: no change.
    """
    name = 'SBR_JNE'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xe)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_15(self):
        return self.get("d15", Type.int_32)

    def fetch_operands(self):
        return self.get_d_15(), self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_15 = args[0]
        d_b = args[1]
        pc = args[2]
        disp4 = args[3]
        cond = d_15 != d_b
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JNZ_Inst(Instruction):
    """ Jump if Not Equal to Zero instruction.
        op = 0xF6
        User Status Flags: no change.
    """
    name = 'SBR_JNZ'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(0x6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b != 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JNZ_A_Inst(Instruction):
    """ Jump if Not Equal to Zero Address instruction.
        op = 0x7C
        User Status Flags: no change.
    """
    name = 'SBR_JNZ.A'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        a_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = a_b != 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JZ_Inst(Instruction):
    """ Jump if Zero instruction.
        op = 0x76
        User Status Flags: no change.
    """
    name = 'SBR_JZ'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(6)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        d_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = d_b == 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_JZ_A_Inst(Instruction):
    """ Jump if Not Equal to Zero Address instruction.
        op = 0xBC
        User Status Flags: no change.
    """
    name = 'SBR_JZ.A'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        a_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = a_b == 0
        dest = pc + (disp4 << 1)
        self.jump(cond, dest)

class SBR_LOOP_Inst(Instruction):
    """ Loop instruction.
        op = 0xFC
        User Status Flags: no change.
    """
    name = 'SBR_LOOP'
    op = "{0}{1}".format(bin(0xf)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"disp4": int(data['a'], 2),
                "b": int(data['b'], 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp4(self):
        return self.constant(self.data['disp4'], Type.int_4).cast_to(Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def get_a_b(self):
        return self.get("a{0}".format(self.data['b']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_b(), self.get_pc(), self.get_disp4()

    def compute_result(self, *args):
        a_b = args[0]
        pc = args[1]
        disp4 = args[2]
        cond = a_b.signed != 0
        dest = pc + ((((1<<27)-1)<<5) | (disp4<<1))
        self.put(a_b - 1, "a{0}".format(self.data['b']))
        self.jump(cond, dest)
