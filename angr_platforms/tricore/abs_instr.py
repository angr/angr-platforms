#!/usr/bin/env python3
""" abs_instr.py
Implementation of ABS format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .rtl import sign_extend_2
from .logger import log_this


class ABS_LD_85_Instructions(Instruction):
    """ ABS_LD_85_Instructions:
        - Load Word instruction:
            op = 0x85
            op2 = 0x00  (2-bit)
            User Status Flags: no change.
        - Load Double-word instruction:
            op = 0x85
            op2 = 0x01  (2-bit)
            User Status Flags: no change.
        - Load Word to Address instruction:
            op = 0x85
            op2 = 0x02  (2-bit)
            User Status Flags: no change.
        - Load Double-word to Address Register instruction:
            op = 0x85
            op2 = 0x03  (2-bit)
            User Status Flags: no change.
    """
    name = 'ABS_LD_85_Instructions ...'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_LD.W'
        elif op2 == 1:
            self.name = 'ABS_LD.D'
        elif op2 == 2:
            self.name = 'ABS_LD.A'
        elif op2 == 3:
            self.name = 'ABS_LD.DA'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        if self.data['op2'] == 0x0:  # LD.W
            return "d{0}".format(self.data['a'])

        elif self.data['op2'] == 0x2:  # LD.A
            return "a{0}".format(self.data['a'])

        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            sys.exit(1)

    def get_op2(self):
        return self.data['op2']

    def get_off18(self):
        return self.data['off18']

    def get_a(self):
        return self.data['a']

    def fetch_operands(self):
        return self.get_a(), self.get_off18(), self.get_op2()

    def compute_result(self, *args):
        a = args[0]
        off18 = args[1]
        op2 = args[2]
        result = ""
        if op2 == 0x0:  # LD.W
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result = self.load(addr, Type.int_32)

        elif op2 == 0x1:  # LD.D
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result_0 = self.load(addr, Type.int_32)
            result_1 = self.load(addr+4, Type.int_32)
            # put result in E[a]
            self.put(result_0, "d{0}".format(a))
            self.put(result_1, "d{0}".format(a+1))

        elif op2 == 0x2:  # LD.A
            addr = self.constant(off18, Type.int_32)
            result = self.load(addr, Type.int_32)

        elif op2 == 0x3:  # LD.DA
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result_0 = self.load(addr, Type.int_32)
            result_1 = self.load(addr+4, Type.int_32)
            # put result in P[a]
            self.put(result_0, "a{0}".format(a))
            self.put(result_1, "a{0}".format(a+1))

        return result

    def commit_result(self, res):
        if self.data['op2'] not in [0x1, 0x3]:  # LD.D/DA put their result themselves
            self.put(res, self.get_dst_reg())

class ABS_LD_05_Instructions(Instruction):
    """ ABS_LD_05_Instructions:
        - Load Byte:
            op = 0x05
            op2 = 0x00
            User Status Flags: no change.
        - Load Byte Unsigned:
            op = 0x05
            op2 = 0x01
            User Status Flags: no change.
        - Load Half-word:
            op = 0x05
            op2 = 0x02
            User Status Flags: no change.
        - Load Half-word Unsigned:
            op = 0x05
            op2 = 0x03
            User Status Flags: no change.
    """
    name = 'ABS_LD_05_Instructions ...'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_LD.B'
        elif op2 == 1:
            self.name = 'ABS_LD.BU'
        elif op2 == 2:
            self.name = 'ABS_LD.H'
        elif op2 == 3:
            self.name = 'ABS_LD.HU'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def compute_result(self, *args):
        result = ""
        if self.data['op2'] == 0x0:  # LD.B
            addr = self.constant(self.data['off18'], Type.int_32)
            result = self.load(addr, Type.int_8)

        elif self.data['op2'] == 0x1:  # LD.BU
            off18 = self.data['off18']
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                               bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result = self.load(addr, Type.int_8)

        elif self.data['op2'] == 0x2:  # LD.H
            off18 = self.data['off18']
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                               bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result = sign_extend_2(self.load(addr, Type.int_16), 16)

        elif self.data['op2'] == 0x3:  # LD.HU
            off18 = self.data['off18']
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                               bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result = self.load(addr, Type.int_16)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class ABS_LD_45_Instructions(Instruction):
    """ ABS_LD_45_Instructions:
        - Load Half-word Signed Fraction:
            op = 0x45
            op2 = 0x00
            User Status Flags: no change.
    """
    name = 'ABS_LD_45_Instructions ...'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_LD.Q'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def compute_result(self, *args):
        result = ""
        if self.data['op2'] == 0x0:  # LD.Q
            off18 = self.data['off18']
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                               bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            addr = self.constant(ea, Type.int_32)
            result = self.load(addr, Type.int_16).cast_to(Type.int_32) << 16

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class ABS_15_Instructions(Instruction):
    """ ABS Instructions with OP=15:
        - Load Lower Context:
            op = 0x15
            op2 = 0x02
            User Status Flags: no change.
        - Load Upper Context:
            op = 0x15
            op2 = 0x03
            User Status Flags: no change.
        - Store Lower Context:
            op = 0x15
            op2 = 0x00
            User Status Flags: no change.
        - Store Upper Context:
            op = 0x15
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'ABS_15_Instructions ...'
    op = "{0}{1}".format(bin(1)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_STLCX'
        elif op2 == 1:
            self.name = 'ABS_STUCX'
        elif op2 == 2:
            self.name = 'ABS_LDLCX'
        elif op2 == 3:
            self.name = 'ABS_LDUCX'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def compute_result(self, *args):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                           bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
        addr = self.constant(int(ea, 2), Type.int_32)
        if self.data['op2'] == 0x0:  # STLCX
            self.store(self.get("pcxi", Type.int_32), addr)
            self.store(self.get("a11", Type.int_32), addr+4)
            self.store(self.get("a2", Type.int_32), addr+8)
            self.store(self.get("a3", Type.int_32), addr+12)
            self.store(self.get("d0", Type.int_32), addr+16)
            self.store(self.get("d1", Type.int_32), addr+20)
            self.store(self.get("d2", Type.int_32), addr+24)
            self.store(self.get("d3", Type.int_32), addr+28)
            self.store(self.get("a4", Type.int_32), addr+32)
            self.store(self.get("a5", Type.int_32), addr+36)
            self.store(self.get("a6", Type.int_32), addr+40)
            self.store(self.get("a7", Type.int_32), addr+44)
            self.store(self.get("d4", Type.int_32), addr+48)
            self.store(self.get("d5", Type.int_32), addr+52)
            self.store(self.get("d6", Type.int_32), addr+56)
            self.store(self.get("d7", Type.int_32), addr+60)

        elif self.data['op2'] == 0x1:  # STUCX
            self.store(self.get("pcxi", Type.int_32), addr)
            self.store(self.get("psw", Type.int_32), addr+4)
            self.store(self.get("a10", Type.int_32), addr+8)
            self.store(self.get("a11", Type.int_32), addr+12)
            self.store(self.get("d8", Type.int_32), addr+16)
            self.store(self.get("d9", Type.int_32), addr+20)
            self.store(self.get("d10", Type.int_32), addr+24)
            self.store(self.get("d11", Type.int_32), addr+28)
            self.store(self.get("a12", Type.int_32), addr+32)
            self.store(self.get("a13", Type.int_32), addr+36)
            self.store(self.get("a14", Type.int_32), addr+40)
            self.store(self.get("a15", Type.int_32), addr+44)
            self.store(self.get("d12", Type.int_32), addr+48)
            self.store(self.get("d13", Type.int_32), addr+52)
            self.store(self.get("d14", Type.int_32), addr+56)
            self.store(self.get("d15", Type.int_32), addr+60)
        elif self.data['op2'] == 0x2:  # LDLCX
            #dummy = self.load(addr, Type.int_32)
            #dummy = self.load(addr+4, Type.int_32)
            self.put(self.load(addr+8, Type.int_32), "a2")
            self.put(self.load(addr+12, Type.int_32), "a3")
            self.put(self.load(addr+16, Type.int_32), "d0")
            self.put(self.load(addr+20, Type.int_32), "d1")
            self.put(self.load(addr+24, Type.int_32), "d2")
            self.put(self.load(addr+28, Type.int_32), "d3")
            self.put(self.load(addr+32, Type.int_32), "a4")
            self.put(self.load(addr+36, Type.int_32), "a5")
            self.put(self.load(addr+40, Type.int_32), "a6")
            self.put(self.load(addr+44, Type.int_32), "a7")
            self.put(self.load(addr+48, Type.int_32), "d4")
            self.put(self.load(addr+52, Type.int_32), "d5")
            self.put(self.load(addr+56, Type.int_32), "d6")
            self.put(self.load(addr+60, Type.int_32), "d7")
        elif self.data['op2'] == 0x3:  # LDUCX
            #dummy = self.load(addr, Type.int_32)
            #dummy = self.load(addr+4, Type.int_32)
            self.put(self.load(addr+8, Type.int_32), "a10")
            self.put(self.load(addr+12, Type.int_32), "a11")
            self.put(self.load(addr+16, Type.int_32), "d8")
            self.put(self.load(addr+20, Type.int_32), "d9")
            self.put(self.load(addr+24, Type.int_32), "d10")
            self.put(self.load(addr+28, Type.int_32), "d11")
            self.put(self.load(addr+32, Type.int_32), "a12")
            self.put(self.load(addr+36, Type.int_32), "a13")
            self.put(self.load(addr+40, Type.int_32), "a14")
            self.put(self.load(addr+44, Type.int_32), "a15")
            self.put(self.load(addr+48, Type.int_32), "d12")
            self.put(self.load(addr+52, Type.int_32), "d13")
            self.put(self.load(addr+56, Type.int_32), "d14")
            self.put(self.load(addr+60, Type.int_32), "d15")

class ABS_E5_Instructions(Instruction):
    """ ABS Instructions with OP=E5:
        - Load-Modify-Store:
            op = 0xE5
            op2 = 0x01
            User Status Flags: no change.
        - Swap with Data Register:
            op = 0xE5
            op2 = 0x00
            User Status Flags: no change.
    """
    name = 'ABS_E5_Instructions ...'
    op = "{0}{1}".format(bin(0xe)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_SWAP.W'
        elif op2 == 1:
            self.name = 'ABS_LDMST'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def compute_result(self, *args):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4),
                                           bin(self.data['off18'] & 0x3fff)[2:].zfill(14))
        addr = self.constant(int(ea, 2), Type.int_32)
        if self.data['op2'] == 0x0:  # SWAP.W
            tmp = self.load(addr, Type.int_32)
            self.store(self.get("d{0}".format(self.data['a']), Type.int_32), addr)
            self.put(tmp, "d{0}".format(self.data['a']))

        elif self.data['op2'] == 0x1:  # LDMST
            self.store(
                (self.load(addr, Type.int_32) & ~self.get("d{0}".format(self.data['a']+1), Type.int_32)) |
                (self.get("d{0}".format(self.data['a']), Type.int_32) &
                 self.get("d{0}".format(self.data['a']+1), Type.int_32))
                , addr)

class ABS_LEA_Instruction(Instruction):
    """ Load Effective Address instruction:
            op = 0xC5
            op2 = 0x00  (2-bit)
            User Status Flags: no change.
    """
    name = 'ABS LEA Instruction'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_LEA'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "a{0}".format(self.data['a'])

    def get_off18(self):
        return self.data['off18']

    def fetch_operands(self):
        return [self.get_off18()]

    def compute_result(self, *args):
        off18 = args[0]
        result = ""
        if self.data['op2'] == 0x0:
            ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
            ea = int(ea, 2)
            result = self.constant(ea, Type.int_32)
        else:
            print("Error: Unknown OP2 '{0}'!".format(self.data['op2']))
            print("ABS instruction OP=C5, OP2=Unknown")
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class ABS_ST_A5_Instructions(Instruction):
    """ ABS_ST_A5_Instructions:
        - Store Word instruction:
            op = 0xA5
            op2 = 0x00  (2-bit)
            User Status Flags: no change.
        - Store Double-word instruction:
            op = 0xA5
            op2 = 0x01  (2-bit)
            User Status Flags: no change.
        - Store Word from Address Register instruction:
            op = 0xA5
            op2 = 0x02  (2-bit)
            User Status Flags: no change.
        - Store Double-word from Address Register instruction:
            op = 0xA5
            op2 = 0x03  (2-bit)
            User Status Flags: no change.
    """
    name = 'ABS_ST_A5_Instructions ...'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_ST.W'
        elif op2 == 1:
            self.name = 'ABS_ST.D'
        elif op2 == 2:
            self.name = 'ABS_ST.A'
        elif op2 == 3:
            self.name = 'ABS_ST.DA'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_addr(self):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
        ea = int(ea, 2)
        addr = self.constant(ea, Type.int_32)
        return addr

    def compute_result(self, *args):
        a = self.data['a']
        result = ""
        if self.data['op2'] == 0x0:  # ST.W
            result = self.get("d{0}".format(a), Type.int_32)

        elif self.data['op2'] == 0x1:  # ST.D
            result_0 = self.get("d{0}".format(a), Type.int_32)
            result_1 = self.get("d{0}".format(a+1), Type.int_32)
            dest_addr = self.get_dst_addr()
            # store result in E[a]
            self.store(result_0, dest_addr)
            self.store(result_1, dest_addr+4)

        elif self.data['op2'] == 0x2:  # ST.A
            result = self.get("a{0}".format(a), Type.int_32)

        elif self.data['op2'] == 0x3:  # ST.DA
            result_0 = self.get("a{0}".format(a), Type.int_32)
            result_1 = self.get("a{0}".format(a+1), Type.int_32)
            dest_addr = self.get_dst_addr()
            # store result in E[a]
            self.store(result_0, dest_addr)
            self.store(result_1, dest_addr+4)

        return result

    def commit_result(self, res):
        if self.data['op2'] not in [0x1, 0x3]:  # ST.D/DA store their result themselves
            self.store(res, self.get_dst_addr())

class ABS_ST_25_Instructions(Instruction):
    """ ABS_ST_25_Instructions:
        - Store Byte:
            op = 0x25
            op2 = 0x00
            User Status Flags: no change.
        - Store Half-word:
            op = 0x25
            op2 = 0x02
            User Status Flags: no change.
    """
    name = 'ABS_ST_25_Instructions ...'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_ST.B'
        elif op2 == 2:
            self.name = 'ABS_ST.H'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_addr(self):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
        ea = int(ea, 2)
        addr = self.constant(ea, Type.int_32)
        return addr

    def compute_result(self, *args):
        result = ""
        a = self.data['a']
        if self.data['op2'] == 0x0:  # ST.B
            result = self.get("d{0}".format(a), Type.int_8).cast_to(Type.int_32)

        elif self.data['op2'] == 0x2:  # ST.H
            result = self.get("d{0}".format(a), Type.int_16).cast_to(Type.int_32)

        return result

    def commit_result(self, res):
        self.store(res, self.get_dst_addr())

class ABS_ST_65_Instructions(Instruction):
    """ ABS_ST_65_Instructions:
        - Store Half-word Signed Fraction:
            op = 0x65
            op2 = 0x00
            User Status Flags: no change.
    """
    name = 'ABS_ST_65_Instructions ...'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(5)[2:].zfill(4))
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
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,   # 17:14
                                                             tmp[6:10].bin,    # 13:10
                                                             tmp[0:4].bin,     # 9:6
                                                             tmp[10:16].bin))  # 5:0
        op2 = int(tmp[4:6].bin, 2)

        if op2 == 0:
            self.name = 'ABS_ST.Q'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "off18": int(off18.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_addr(self):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
        ea = int(ea, 2)
        addr = self.constant(ea, Type.int_32)
        return addr

    def compute_result(self, *args):
        result = ""
        if self.data['op2'] == 0x0:  # ST.Q
            result = self.get("d{0}".format(self.data['a']), Type.int_32) >> 16

        return result

    def commit_result(self, res):
        self.store(res, self.get_dst_addr())
