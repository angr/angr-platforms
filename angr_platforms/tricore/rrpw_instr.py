#!/usr/bin/env python3
""" rrpw_instr.py
Implementation of RRPW format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import extend_to_32_bits, sign_extend
from .logger import log_this


class RRPW_OP_37_Instructions(Instruction):
    """ RRPW instructions:
        - Insert Bit Field instruction:
            op = 0x37
            op2 = 0x00  (2-bit)
            User Status Flags: no change.
        - Insert Mask instruction:
            op = 0x37
            op2 = 0x01  (2-bit)
            User Status Flags: no change.
        - Extract Bit Field instruction:
            op = 0x37
            op2 = 0x02  (2-bit)
            User Status Flags: no change.
        - Extract Bit Field Unsigned instruction:
            op = 0x37
            op2 = 0x03  (2-bit)
            User Status Flags: no change.
    """
    name = 'RRPW_OP_37_Instructions ...'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(7)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = int(tmp[20:24].hex, 16)
        b = int(tmp[16:20].hex, 16)
        w = int(tmp[11:16].bin.zfill(8), 2)
        op2 = int(tmp[9:11].bin, 2)
        p = int(tmp[4:9].bin.zfill(8), 2)
        c = int(tmp[:4].hex, 16)

        if op2 == 0:
            self.name = "RRPW_INSERT"
        elif op2 == 1:
            self.name = "RRPW_IMASK"
        elif op2 == 2:
            self.name = "RRPW_EXTR"
        elif op2 == 3:
            self.name = "RRPW_EXTR.U"
        else:
            self.name = "UNKNOWN"

        data = {"a": a,
                "b": b,
                "c": c,
                "w": w,
                "p": p,
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        pos = self.data["p"]
        width = self.data["w"]
        if (pos + width > 32) or (width == 0):
            print("Error: Undefined result for (pos + width > 32)!")
            sys.exit(1)

        result = ""
        if self.data['op2'] == 0:  # INSERT
            mask = (2**width) - 1 << pos
            result = (d_a & ~mask) | ((d_b << pos) & mask)

        elif self.data['op2'] == 1:  # IMASK
            const_1 = self.constant(1, Type.int_32)
            result_1 = ((const_1 << width)-1) << pos
            result_2 = d_b << pos

            # undefined result if (pos + width) > 32
            cond_undefined = extend_to_32_bits(((pos + width) >> 5) == 0)
            result_1 = result_1 & cond_undefined
            result_2 = result_2 & cond_undefined

            self.put(result_1, "d{0}".format(self.data['c']+1))
            self.put(result_2, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 2:  # EXTR
            mask = (1 << width) - 1
            result = sign_extend((d_a >> pos) & mask, width)

        elif self.data['op2'] == 3:  # EXTR.U
            mask = (1 << width) - 1
            result = (d_a >> pos) & mask

        return result

    def commit_result(self, res):
        if self.data['op2'] != 1:  # IMASK PUTs its results itself.
            self.put(res, self.get_dst_reg())

class RRPW_OP_77_Instructions(Instruction):
    """ Extract Bit Field instruction.
        op = 0x77
        op2 = 0x00  2-bit
        User Status Flags: no change.
    """
    name = 'RRPW_OP_77_Instructions ...'
    op = "{0}{1}".format(bin(7)[2:].zfill(4), bin(7)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(2))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = int(tmp[20:24].hex, 16)
        b = int(tmp[16:20].hex, 16)
        op2 = int(tmp[9:11].bin, 2)
        pos = int(tmp[4:9].bin.zfill(8), 2)
        c = int(tmp[:4].hex, 16)

        if op2 == 0:
            self.name = "RRPW_DEXTR"
        else:
            self.name = "UNKNOWN"

        data = {"a": a,
                "b": b,
                "op2": op2,
                "pos": pos,
                "c": c}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        result = ""
        if self.data['op2'] == 0:  # RRPW_DEXTR
            pos = self.data["pos"]
            tmp_1 = d_a << pos
            tmp_2 = (d_b & (((1 << pos)-1) << (32 - pos))) >> (32 - pos)
            result = tmp_1 | tmp_2

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
