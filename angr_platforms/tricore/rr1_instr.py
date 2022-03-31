#!/usr/bin/env python3
""" rr1_instr.py
Implementation of RR1 format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class RR1_MUL_H_B3_Instructions(Instruction):
    """ RR1 Packed Multiply Q Format Instructions:
            - MUL.H LL instruction:
                op = 0xB3
                op2 = 0x1A  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.H LU instruction:
                op = 0xB3
                op2 = 0x19  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.H UL instruction:
                op = 0xB3
                op2 = 0x18  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.H UU instruction:
                op = 0xB3
                op2 = 0x1B  (10 bits)
                User Status Flags: V, AV, SAV
        RR1 Packed Multiply Q Format-Multi-percision Instructions:
            - MULM.H LL instruction:
                op = 0xB3
                op2 = 0x1E  (10 bits)
                User Status Flags: V, AV
            - MULM.H LU instruction:
                op = 0xB3
                op2 = 0x1D  (10 bits)
                User Status Flags: V, AV
            - MULM.H UL instruction:
                op = 0xB3
                op2 = 0x1C  (10 bits)
                User Status Flags: V, AV
            - MULM.H UU instruction:
                op = 0xB3
                op2 = 0x1F  (10 bits)
                User Status Flags: V, AV
        RR1 Packed Multiply Q Format with Rounding Instructions:
            - MULR.H LL instruction:
                op = 0xB3
                op2 = 0x0E  (10 bits)
                User Status Flags: V, AV, SAV
            - MULR.H LU instruction:
                op = 0xB3
                op2 = 0x0D  (10 bits)
                User Status Flags: V, AV, SAV
            - MULR.H UL instruction:
                op = 0xB3
                op2 = 0x0C  (10 bits)
                User Status Flags: V, AV, SAV
            - MULR.H UU instruction:
                op = 0xB3
                op2 = 0x0F  (10 bits)
                User Status Flags: V, AV, SAV
    """
    name = 'RR1_MUL_H_B3_Instructions ...'
    op = "{0}{1}".format(bin(0xb)[2:].zfill(4), bin(3)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = bitstring.BitArray(bin="{0}".format(tmp[20:24].bin))
        b = bitstring.BitArray(bin="{0}".format(tmp[16:20].bin))
        n = bitstring.BitArray(bin="{0}".format(tmp[14:16].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:14].bin))
        op2 = int(op2.bin, 2)
        c = tmp[:4]

        if op2 == 0x1a:
            self.name = 'RR1_MUL.H LL'
        elif op2 == 0x19:
            self.name = 'RR1_MUL.H LU'
        elif op2 == 0x18:
            self.name = 'RR1_MUL.H UL'
        elif op2 == 0x1b:
            self.name = 'RR1_MUL.H UU'
        elif op2 == 0x1e:
            self.name = 'RR1_MULM.H LL'
        elif op2 == 0x1d:
            self.name = 'RR1_MULM.H LU'
        elif op2 == 0x1c:
            self.name = 'RR1_MULM.H UL'
        elif op2 == 0x1f:
            self.name = 'RR1_MULM.H UU'
        elif op2 == 0xe:
            self.name = 'RR1_MULR.H LL'
        elif op2 == 0xd:
            self.name = 'RR1_MULR.H LU'
        elif op2 == 0xc:
            self.name = 'RR1_MULR.H UL'
        elif op2 == 0xf:
            self.name = 'RR1_MULR.H UU'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "n": int(n.bin, 2),
                "c": int(c.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        result = ""
        result_word0 = ""
        result_word1 = ""
        if self.data['op2'] == 0x1a:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result_word0, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result_word1, "d{0}".format(self.data['c']+1))  # E[c][62:32]

        elif self.data['op2'] == 0x19:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result_word0, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result_word1, "d{0}".format(self.data['c']+1))  # E[c][62:32]

        elif self.data['op2'] == 0x18:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result_word0, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result_word1, "d{0}".format(self.data['c']+1))  # E[c][62:32]

        elif self.data['op2'] == 0x1b:
            sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result_word0, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result_word1, "d{0}".format(self.data['c']+1))  # E[c][62:32]

        elif self.data['op2'] == 0x1e:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (cond_sc0^0xffffffff)
            result = (result_word1.cast_to(Type.int_64) + result_word0.cast_to(Type.int_64)) << 16
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32, "d{0}".format(self.data['c']+1))         # E[c][62:32]

        elif self.data['op2'] == 0x1d:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (cond_sc0^0xffffffff)
            result = (result_word1.cast_to(Type.int_64) + result_word0.cast_to(Type.int_64)) << 16
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32, "d{0}".format(self.data['c']+1))         # E[c][62:32]

        elif self.data['op2'] == 0x1c:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (cond_sc0^0xffffffff)
            result = (result_word1.cast_to(Type.int_64) + result_word0.cast_to(Type.int_64)) << 16
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32, "d{0}".format(self.data['c']+1))         # E[c][62:32]

        elif self.data['op2'] == 0x1f:
            sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_word1 = (0x7fffffff & cond_sc1) | \
                           ((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) & (cond_sc1^0xffffffff)
            result_word0 = (0x7fffffff & cond_sc0) | \
                           ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (cond_sc0^0xffffffff)
            result = (result_word1.cast_to(Type.int_64) + result_word0.cast_to(Type.int_64)) << 16
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32, "d{0}".format(self.data['c']+1))         # E[c][62:32]

        elif self.data['op2'] == 0xe:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_hw1 = (0x7fffffff & cond_sc1) | \
                         (((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) + 0x8000) & (cond_sc1^0xffffffff)
            result_hw0 = (0x7fffffff & cond_sc0) | \
                         (((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            result = ((result_hw1 >> 16) << 16) | (result_hw0 >> 16)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 0xd:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_hw1 = (0x7fffffff & cond_sc1) | \
                         (((extract_16s(d_a,1) * extract_16s(d_b,0)) << n.value) + 0x8000) & (cond_sc1^0xffffffff)
            result_hw0 = (0x7fffffff & cond_sc0) | \
                         (((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            result = ((result_hw1 >> 16) << 16) | (result_hw0 >> 16)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 0xc:
            sc1 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_hw1 = (0x7fffffff & cond_sc1) | \
                         (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) + 0x8000) & (cond_sc1^0xffffffff)
            result_hw0 = (0x7fffffff & cond_sc0) | \
                         (((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            result = ((result_hw1 >> 16) << 16) | (result_hw0 >> 16)
            self.put(result, "d{0}".format(self.data['c']))

        elif self.data['op2'] == 0xf:
            sc1 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) &
                                    ((d_b >> 16) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc1 = extend_to_32_bits(sc1 != 0)
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result_hw1 = (0x7fffffff & cond_sc1) | \
                         (((extract_16s(d_a,0) * extract_16s(d_b,1)) << n.value) + 0x8000) & (cond_sc1^0xffffffff)
            result_hw0 = (0x7fffffff & cond_sc0) | \
                         (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            result = ((result_hw1 >> 16) << 16) | (result_hw0 >> 16)
            self.put(result, "d{0}".format(self.data['c']))

        # set flags
        c = 0
        v = 0
        if self.data['op2'] in [0xe, 0xd, 0xc, 0xf]:
            av = advanced_overflow(result)
        else:
            av0 = advanced_overflow(result_word0)
            av1 = advanced_overflow(result_word1)
            av = av1 | av0
        psw = self.get_psw()
        sv = 0
        if self.data['op2'] in [0x1e, 0x1d, 0x1c, 0x1f]:
            sav = 0
        else:
            sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

class RR1_MUL_Q_93_Instructions(Instruction):
    """ RR1 Multiply Q Format Instructions:
            - MUL.Q (32-bit) instruction:
                op = 0x93
                op2 = 0x02  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q (64-bit) instruction:
                op = 0x93
                op2 = 0x1B  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q L (32-bit) instruction:
                op = 0x93
                op2 = 0x01  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q L (64-bit) instruction:
                op = 0x93
                op2 = 0x19  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q U (32-bit) instruction:
                op = 0x93
                op2 = 0x00  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q U (64-bit) instruction:
                op = 0x93
                op2 = 0x18  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q LL (32-bit) instruction:
                op = 0x93
                op2 = 0x05  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q UU (32-bit) instruction:
                op = 0x93
                op2 = 0x04  (10 bits)
                User Status Flags: V, AV, SAV

        RR1 Multiply Q Format with Rounding Instructions:
            - MUL.Q UU (32-bit) instruction:
                op = 0x93
                op2 = 0x07  (10 bits)
                User Status Flags: V, AV, SAV
            - MUL.Q UU (32-bit) instruction:
                op = 0x93
                op2 = 0x06  (10 bits)
                User Status Flags: V, AV, SAV
    """
    name = 'RR1_MUL_Q_93_Instructions ...'
    op = "{0}{1}".format(bin(9)[2:].zfill(4), bin(3)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        a = bitstring.BitArray(bin="{0}".format(tmp[20:24].bin))
        b = bitstring.BitArray(bin="{0}".format(tmp[16:20].bin))
        n = bitstring.BitArray(bin="{0}".format(tmp[14:16].bin))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[4:14].bin))
        op2 = int(op2.bin, 2)
        c = tmp[:4]

        if op2 == 0x2:
            self.name = 'RR1_MUL.Q (32-bit)'
        elif op2 == 0x1b:
            self.name = 'RR1_MUL.Q (64-bit)'
        elif op2 == 0x1:
            self.name = 'RR1_MUL.Q L (32-bit)'
        elif op2 == 0x19:
            self.name = 'RR1_MUL.Q L (64-bit)'
        elif op2 == 0x0:
            self.name = 'RR1_MUL.Q U (32-bit)'
        elif op2 == 0x18:
            self.name = 'RR1_MUL.Q U (64-bit)'
        elif op2 == 0x5:
            self.name = 'RR1_MUL.Q LL (32-bit)'
        elif op2 == 0x4:
            self.name = 'RR1_MUL.Q UU (32-bit)'
        elif op2 == 0x7:
            self.name = 'RR1_MULR.Q LL (32-bit)'
        elif op2 == 0x6:
            self.name = 'RR1_MULR.Q UU (32-bit)'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "b": int(b.bin, 2),
                "n": int(n.bin, 2),
                "c": int(c.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_n(self):
        return self.constant(self.data['n'], Type.int_2)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_n()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        n = args[2]
        op2 = self.data['op2']
        if op2 == 0x2:  # RR1_MUL.Q (32-bit)
            result = (((d_a.cast_to(Type.int_64, signed=True) *
                        d_b.cast_to(Type.int_64, signed=True)) << n.value) >> 32).cast_to(Type.int_32)
            self.put(result, "d{0}".format(self.data['c']))

        elif op2 == 0x1b:  # RR1_MUL.Q (64-bit)
            result = (d_a * d_b) << n.value
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32, "d{0}".format(self.data['c']+1))         # E[c][62:32]

        elif op2 == 0x1:  # RR1_MUL.Q L (32-bit)
            result = ((d_a.signed * extract_16s(d_b,0)) << n.value) >> 16
            self.put(result, "d{0}".format(self.data['c']))

        elif op2 == 0x19:  # RR1_MUL.Q L (64-bit)
            result = ((d_a.cast_to(Type.int_64, signed=True) *
                       extract_16s(d_b,0).cast_to(Type.int_64, signed=True)) << n.value)
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32 , "d{0}".format(self.data['c']+1))        # E[c][62:32]

        elif op2 == 0x0:  # RR1_MUL.Q U (32-bit)
            result = ((d_a.signed * extract_16s(d_b,1)) << n.value) >> 16
            self.put(result, "d{0}".format(self.data['c']))

        elif op2 == 0x18:  # RR1_MUL.Q U (64-bit)
            result = ((d_a.cast_to(Type.int_64, signed=True) *
                       extract_16s(d_b,1).cast_to(Type.int_64, signed=True)) << n.value)
            self.put(result & 0xffffffff, "d{0}".format(self.data['c']))    # E[c][31:0]
            self.put(result >> 32 , "d{0}".format(self.data['c']+1))        # E[c][62:32]

        elif op2 == 0x5:  # RR1_MUL.Q LL (32-bit)
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result = (0x7fffffff & cond_sc0) | \
                     ((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result, "d{0}".format(self.data['c']))

        elif op2 == 0x4:  # RR1_MUL.Q UU (32-bit)
            sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result = (0x7fffffff & cond_sc0) | \
                     ((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) & (cond_sc0^0xffffffff)
            self.put(result, "d{0}".format(self.data['c']))

        elif op2 == 0x7:  # RR1_MULR.Q LL (32-bit)
            sc0 = extend_to_32_bits(((d_a & 0xffff) == 0x8000) &
                                    ((d_b & 0xffff) == 0x8000) &
                                    (n == 1).cast_to(Type.int_32))
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result = (0x7fffffff & cond_sc0) | \
                     (((extract_16s(d_a,0) * extract_16s(d_b,0)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            self.put(((result >> 16) << 16), "d{0}".format(self.data['c']))

        elif op2 == 0x6:  # RR1_MULR.Q UU (32-bit)
            sc0 = extend_to_32_bits(((d_a >> 16) == 0x8000) & ((d_b >> 16) == 0x8000) & (n == 1).cast_to(Type.int_32))
            cond_sc0 = extend_to_32_bits(sc0 != 0)
            result = (0x7fffffff & cond_sc0) | \
                     (((extract_16s(d_a,1) * extract_16s(d_b,1)) << n.value) + 0x8000) & (cond_sc0^0xffffffff)
            self.put(((result >> 16) << 16), "d{0}".format(self.data['c']))

        # set flags
        c = 0
        if op2 in [0x2, 0x1, 0x0, 0x7]:  # 32-bit
            v = overflow(result).cast_to(Type.int_32)
            av = advanced_overflow(result).cast_to(Type.int_32)
        else:  # 64-bit
            v = overflow_64(result).cast_to(Type.int_32)
            av = advanced_overflow_64(result).cast_to(Type.int_32)
        psw = self.get_psw()
        if op2 in [0x7, 0x6]:
            sv = 0
        else:
            sv = v
        sav = av
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")
