#!/usr/bin/env python3
""" rlc_instr.py
Implementation of RLC format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import set_usb
from .logger import log_this


class RLC_ADDI_Inst(Instruction):
    """ Add Immediate instruction.
        op = 0x1B
        User Status Flags: V, SV, AV, SAV
    """
    name = 'RLC_ADDI'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"a": int(a.hex, 16),
                "const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_16).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const16()

    def compute_result(self, *args):
        d_a = args[0]
        const16 = args[1]
        result = d_a + const16

        # set flags
        c = 0
        v = (result >> 32 != 0)
        sv = v
        av = result[31] ^ result[30]
        sav = av
        psw = self.get_psw()
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_ADDIH(Instruction):
    """ Add Immediate High instruction.
        op = 0x9B
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'RLC_ADDIH'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"a": int(a.hex, 16),
                "const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const16()

    def compute_result(self, *args):
        d_a = args[0]
        const16 = args[1]
        return d_a + (const16 << 16)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_ADDIH_A(Instruction):
    """ Add Immediate High to Address.
        op = 0x11
        User Status Flags: no change
    """
    name = 'RLC_ADDIH.A'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(1)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"a": int(a.hex, 16),
                "const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_a_a(), self.get_const16()

    def compute_result(self, *args):
        a_a = args[0]
        const16 = args[1]
        return a_a + (const16 << 16)

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MFCR(Instruction):
    """ Move From Core Register.
        op = 0x4D
        User Status Flags: no change
        Note: PSW is handled with offset=0xfe04.
              Other offset should be considered seperately.
    """
    name = 'RLC_MFCR'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const16()]

    def compute_result(self, *args):
        const16 = args[0]
        result = ""
        if const16 == 0xfe04:
            result = self.get_psw()
        else:
            print("Unknown offset '{0}' for MFCR.".format(const16))

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MOV(Instruction):
    """ Move.
        op = 0x3B
        User Status Flags: no change
    """
    name = 'RLC_MOV'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const16()]

    def compute_result(self, *args):
        const16 = args[0]
        return const16

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MOV_U(Instruction):
    """ Move Unsigned.
        op = 0xBB
        User Status Flags: no change.
    """
    name = 'RLC_MOV.U'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const16()]

    def compute_result(self, *args):
        const16 = args[0]
        return const16

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MOVH(Instruction):
    """ Move High instruction.
        op = 0x7B
        User Status Flags: no change
    """
    name = 'RLC_MOVH'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(0xb)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const16()]

    def compute_result(self, *args):
        const16 = args[0]
        return const16 << 16

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MOVH_A(Instruction):
    """ Move High to Address.
        op = 0x91
        User Status Flags: no change
    """
    name = 'RLC_MOVH.A'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(1)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        c = tmp[:4]
        data = {"const16": int(const16.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['c'])

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def fetch_operands(self):
        return [self.get_const16()]

    def compute_result(self, *args):
        const16 = args[0]
        return const16 << 16

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class RLC_MTCR(Instruction):
    """ Move To Core Register.
        op = 0xCD
        User Status Flags: no change
        Note: PSW is handled with offset=0xfe04.
              Other offset should be considered seperately.
    """
    name = 'RLC_MTCR'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = tmp[20:24]
        const16 = bitstring.BitArray(bin="{0}".format(tmp[4:20].bin))
        data = {"const16": int(const16.hex, 16),
                "a": int(a.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_const16(self):
        return self.constant(self.data['const16'], Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_const16()

    def compute_result(self, *args):
        d_a = args[0]
        const16 = args[1]

        # set flags
        c = 0
        v = 0
        sv = 0
        av = 0
        sav = 0
        if const16 == 0xfe04:
            c = d_a[31]
            v = d_a[30]
            sv = d_a[29]
            av = d_a[28]
            sav = d_a[27]
        psw = self.get_psw()
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")
