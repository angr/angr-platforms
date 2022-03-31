#!/usr/bin/env python3
""" rrrw_instr.py
Implementation of RRRW format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import extend_to_32_bits, sign_extend_2
from .logger import log_this


class RRRW_Instructions(Instruction):
    """ RRRW instructions:
        - Insert Bit Field instruction.
            op = 0x57
            op2 = 0x00  (3-bit)
            User Status Flags: no change.
        - Insert Mask instruction:
            op = 0x57
            op2 = 0x01  (3-bit)
            User Status Flags: no change.
        - Extract Bit Field:
            op = 0x57
            op2 = 0x02  (3-bit)
            User Status Flags: no change.
        - Extract Bit Field Unsigned:
            op = 0x57
            op2 = 0x03  (3-bit)
            User Status Flags: no change.
    """
    name = 'RRRW_Instructions'
    op = "{0}{1}".format(bin(5)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        op2 = int(tmp[8:11].bin, 2)
        d = int(tmp[4:8].hex, 16)
        c = int(tmp[:4].hex, 16)

        if op2 == 0:
            self.name = "RRRW_INSERT"
        elif op2 == 1:
            self.name = "RRRW_IMASK"
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
                "d": d,
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_d(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_d()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_d = args[2]
        pos = (d_d & 0x1f).cast_to(Type.int_8)
        width = self.data["w"]

        # undefined result if (pos + width) > 32
        cond_undefined = extend_to_32_bits(((pos.cast_to(Type.int_32) + width) >> 5) == 0)

        result = ""
        if self.data['op2'] == 0:  # INSERT
            mask = (((2**width) - 1) << pos).cast_to(Type.int_32)
            result = ((d_a & ~mask) | ((d_b << pos) & mask)) & cond_undefined

        elif self.data['op2'] == 1:  # IMASK
            const_1 = self.constant(1, Type.int_32)
            result_1 = ((const_1 << width)-1) << pos
            result_2 = d_b << pos

            result_1 = result_1 & cond_undefined
            result_2 = result_2 & cond_undefined

            self.put(result_1, "d{0}".format(self.data['c']+1))
            self.put(result_2, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 2:  # EXTR
            mask = (1 << width) - 1
            result = sign_extend_2((d_a >> pos) & mask, width) & cond_undefined

        elif self.data['op2'] == 3:  # EXTR.U
            mask = (1 << width) - 1
            result = ((d_a >> pos) & mask) & cond_undefined

        return result

    def commit_result(self, res):
        if self.data['op2'] != 1:  # IMASK PUTs its results itself.
            self.put(res, self.get_dst_reg())
