#!/usr/bin/env python3
""" b_instr.py
Implementation of B format instructions.
"""
from pyvex.lifting.util import Type, Instruction, JumpKind
import bitstring
from .logger import log_this


class B_CALL_Inst(Instruction):
    """ Call instruction.
        op = 0x6D
        User Status Flags: no change.
    """
    name = 'B_CALL'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['a'],
                                                                    data['b'],
                                                                    data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d']))
        data = {"disp24": int(disp24.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24']<<1, Type.int_24).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return self.get_pc(), self.get_disp24()

    def compute_result(self, *args):
        pc = args[0]
        disp24 = args[1]
        MASK_FCX_FCXS = 0x000f0000
        MASK_FCX_FCXO = 0x0000ffff
        fcx = self.get("fcx", Type.int_32)
        ea = ((fcx & MASK_FCX_FCXS) << 12) + ((fcx & MASK_FCX_FCXO) << 6)
        new_fcx = self.load(ea, Type.int_32)

        # save context upper
        pcxi = self.get("pcxi", Type.int_32)
        self.store(pcxi, ea)
        psw = self.get("psw", Type.int_32)
        self.store(psw, ea+4)
        a10 = self.get("a10", Type.int_32)
        self.store(a10, ea+8)
        a11 = self.get("a11", Type.int_32)
        self.store(a11, ea+12)
        d8 = self.get("d8", Type.int_32)
        self.store(d8, ea+16)
        d9 = self.get("d9", Type.int_32)
        self.store(d9, ea+20)
        d10 = self.get("d10", Type.int_32)
        self.store(d10, ea+24)
        d11 = self.get("d11", Type.int_32)
        self.store(d11, ea+28)
        a12 = self.get("a12", Type.int_32)
        self.store(a12, ea+32)
        a13 = self.get("a13", Type.int_32)
        self.store(a13, ea+36)
        a14 = self.get("a14", Type.int_32)
        self.store(a14, ea+40)
        a15 = self.get("a15", Type.int_32)
        self.store(a15, ea+44)
        d12 = self.get("d12", Type.int_32)
        self.store(d12, ea+48)
        d13 = self.get("d13", Type.int_32)
        self.store(d13, ea+52)
        d14 = self.get("d14", Type.int_32)
        self.store(d14, ea+56)
        d15 = self.get("d15", Type.int_32)
        self.store(d15, ea+60)

        # PCXI[19:0] = FCX[19:0]
        pcxi = (pcxi >> 20) << 20 | (fcx & 0xfffff)
        self.put(pcxi, "pcxi")

        # FCX[19:0] = new_FCX[19:0]
        fcx = (fcx >> 20) << 20 | (new_fcx & 0xfffff)
        self.put(fcx, "fcx")

        ret_addr = (pc + 4)
        self.put(ret_addr, "a11")

        dest = pc + disp24
        self.jump(None, dest, jumpkind=JumpKind.Call)

class B_CALLA_Inst(Instruction):
    """ Call Absolute instruction.
        op = 0xED
        User Status Flags: no change.
    """
    name = 'B_CALLA'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['a'],
                                                                    data['b'],
                                                                    data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d']))
        data = {"disp24": int(disp24.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24'], Type.int_24)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return self.get_pc(), self.get_disp24()

    def compute_result(self, *args):
        pc = args[0]
        disp24 = args[1]
        MASK_FCX_FCXS = 0x000f0000
        MASK_FCX_FCXO = 0x0000ffff
        fcx = self.get("fcx", Type.int_32)
        ea = ((fcx & MASK_FCX_FCXS) << 12) + ((fcx & MASK_FCX_FCXO) << 6)
        new_fcx = self.load(ea, Type.int_32)

        # save context upper
        pcxi = self.get("pcxi", Type.int_32)
        self.store(pcxi, ea)
        psw = self.get("psw", Type.int_32)
        self.store(psw, ea+4)
        a10 = self.get("a10", Type.int_32)
        self.store(a10, ea+8)
        a11 = self.get("a11", Type.int_32)
        self.store(a11, ea+12)
        d8 = self.get("d8", Type.int_32)
        self.store(d8, ea+16)
        d9 = self.get("d9", Type.int_32)
        self.store(d9, ea+20)
        d10 = self.get("d10", Type.int_32)
        self.store(d10, ea+24)
        d11 = self.get("d11", Type.int_32)
        self.store(d11, ea+28)
        a12 = self.get("a12", Type.int_32)
        self.store(a12, ea+32)
        a13 = self.get("a13", Type.int_32)
        self.store(a13, ea+36)
        a14 = self.get("a14", Type.int_32)
        self.store(a14, ea+40)
        a15 = self.get("a15", Type.int_32)
        self.store(a15, ea+44)
        d12 = self.get("d12", Type.int_32)
        self.store(d12, ea+48)
        d13 = self.get("d13", Type.int_32)
        self.store(d13, ea+52)
        d14 = self.get("d14", Type.int_32)
        self.store(d14, ea+56)
        d15 = self.get("d15", Type.int_32)
        self.store(d15, ea+60)

        # PCXI[19:0] = FCX[19:0]
        pcxi = (pcxi >> 20) << 20 | (fcx & 0xfffff)
        self.put(pcxi, "pcxi")

        # FCX[19:0] = new_FCX[19:0]
        fcx = (fcx >> 20) << 20 | (new_fcx & 0xfffff)
        self.put(fcx, "fcx")

        ret_addr = (pc + 4)
        self.put(ret_addr, "a11")

        dest = ((disp24 >> 20) << 28) | ((disp24 & 0xfffff) << 1)
        self.jump(None, dest, jumpkind=JumpKind.Call)

class B_J_Inst(Instruction):
    """ Jump Unconditional instruction.
        op = 0x1D
        User Status Flags: no change.
    """
    name = 'B_J'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d'],
                                                                    data['a'],
                                                                    data['b']))
        disp24 = bitstring.BitArray(bin="{0}{1}".format(disp24.bin[16:24], disp24.bin[0:16]))
        data = {"disp24": int(disp24.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24'], Type.int_24).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return [self.get_pc(), self.get_disp24()]

    def compute_result(self, *args):
        pc = args[0]
        disp24 = args[1]
        dest = pc + (disp24 << 1)
        self.jump(None, dest)

class B_JA_Inst(Instruction):
    """ Jump Unconditional Absolute instruction.
        op = 0x9D
        User Status Flags: no change.
    """
    name = 'B_JA'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['a'],
                                                                    data['b'],
                                                                    data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d']))
        data = {"disp24": int(disp24.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24'], Type.int_32)

    def fetch_operands(self):
        return [self.get_disp24()]

    def compute_result(self, *args):
        disp24 = args[0]
        dest = ((disp24 >> 20) << 28) | ((disp24 & 0xfffff) << 1)
        self.jump(None, dest)

class B_JL_Inst(Instruction):
    """ Jump and Link Unconditional instruction.
        op = 0x5D
        User Status Flags: no change.
    """
    name = 'B_JL'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['a'],
                                                                    data['b'],
                                                                    data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d']))
        data = {"disp24": int(disp24.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24'], Type.int_24).cast_to(Type.int_32, signed=True)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return [self.get_pc(), self.get_disp24()]

    def compute_result(self, *args):
        pc = args[0]
        disp24 = args[1]
        ret_addr = pc + 4
        dest = pc + (disp24 << 1)
        self.put(ret_addr, "a11")
        self.jump(None, dest)

class B_JLA_Inst(Instruction):
    """ Jump and Link Absolute instruction.
        op = 0xDD
        User Status Flags: no change.
    """
    name = 'B_JLA'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        disp24 = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['a'],
                                                                    data['b'],
                                                                    data['e'],
                                                                    data['f'],
                                                                    data['c'],
                                                                    data['d']))
        data = {"disp24": int(disp24.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp24(self):
        return self.constant(self.data['disp24'], Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return [self.get_pc(), self.get_disp24()]

    def compute_result(self, *args):
        pc = args[0]
        disp24 = args[1]
        ret_addr = pc + 4
        dest = ((disp24 >> 20) << 28) | ((disp24 & 0xfffff) << 1)
        self.put(ret_addr, "a11")
        self.jump(None, dest)
