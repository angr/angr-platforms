#!/usr/bin/env python3
""" rcrr_instr.py
Implementation of RCRR format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class RCRR_Instructions(Instruction):
    """ Insert Bit Field instruction.
        op = 0x97
        op2 = 0x00  3-bit
        User Status Flags: no change.
    """
    name = 'RCRR_Instructions ...'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        const4 = int(tmp[16:20].hex, 16)
        w = int(tmp[11:16].bin.zfill(8), 2)
        op2 = int(tmp[8:11].bin, 2)
        d = int(tmp[4:8].hex, 16)
        c = int(tmp[:4].hex, 16)

        if op2 == 0:
            self.name = "RCRR_INSERT"
        else:
            self.name = "UNKNOWN"

        data = {"a": a,
                "const4": const4,
                "c": c,
                "w": w,
                "d": d,
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_const4(self):
        return self.constant(self.data['const4'], Type.int_32)

    def get_d_d_2(self):
        return self.get("d{0}".format(self.data['d']+1), Type.int_32)

    def get_d_d_1(self):
        return self.get("d{0}".format(self.data['d']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_d_1(), self.get_d_d_2(), self.get_const4()

    def compute_result(self, *args):
        d_a = args[0]
        d_d_1 = args[1]
        d_d_2 = args[2]
        const4 = args[3]
        # E[d] = d_d_2 | d_d_1
        pos = d_d_1 & 0x1f
        width = d_d_2 & 0x1f
        #TODO if (pos + width > 32) or (width == 0):
        #        print("Undefined result for (pos + width > 32)!")
        #        exit(1)

        result = ""
        if self.data['op2'] == 0:
            const_2 = self.constant(2, Type.int_8)
            power_2_cond_1 = ((width & 1) == 1).cast_to(Type.int_8)
            power_2_cond_2 = ((width >> 1 & 1) == 1).cast_to(Type.int_8)
            power_2_cond_3 = ((width >> 2 & 1) == 1).cast_to(Type.int_8)
            power_2_cond_4 = ((width >> 3 & 1) == 1).cast_to(Type.int_8)
            power_2_cond_5 = ((width >> 4 & 1) == 1).cast_to(Type.int_8)
            power_2_calc = ((((const_2 << power_2_cond_1) <<
                              power_2_cond_2) << power_2_cond_3) << power_2_cond_4) << power_2_cond_5
            mask = ((power_2_calc - 1) << pos.cast_to(Type.int_8)).cast_to(Type.int_32)
            result = (d_a & ~mask) | ((const4 << pos.cast_to(Type.int_8)) & mask)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
