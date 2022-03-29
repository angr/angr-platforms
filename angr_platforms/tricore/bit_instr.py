#!/usr/bin/env python3
""" bit_instr.py
Implementation of BIT format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class BIT_Acc_Logical_AND_Inst(Instruction):
    """ Accumulating Bit Logical AND instructions.
        - AND-AND:
            op = 0x47
            op2 = 0x00
            User Status Flags: no change.
        - AND-AND-Not:
            op = 0x47
            op2 = 0x03
            User Status Flags: no change.
        - AND-NOR:
            op = 0x47
            op2 = 0x02
            User Status Flags: no change.
        - AND-OR:
            op = 0x47
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'BIT_Acc_Logical_AND_Inst ...'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11]))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_AND.AND.T"
        elif op2 == 0x3:
            self.name = "BIT_AND.ANDN.T"
        elif op2 == 0x2:
            self.name = "BIT_AND.NOR.T"
        elif op2 == 0x1:
            self.name = "BIT_AND.OR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        result = ""
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        if self.data['op2'] == 0x0:  # AND.AND.T
            result = (d_c & 0xfe) | ((d_c & 0x1) & (((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1)))

        elif self.data['op2'] == 0x3:  # AND.ANDN.T
            result = (d_c & 0xfe) | ((d_c & 0x1) & (((d_a >> pos1) & 0x1) & (((d_b >> pos2) & 0x1) ^ 0x1)))

        elif self.data['op2'] == 0x2:  # AND.NOR.T
            result = (d_c & 0xfe) | ((d_c & 0x1) & ((((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)) ^ 0x1))

        elif self.data['op2'] == 0x1:  # AND.OR.T
            result = (d_c & 0xfe) | ((d_c & 0x1) & (((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)))

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Acc_Logical_OR_Inst(Instruction):
    """ Accumulating Bit Logical OR instructions.
        - OR-AND:
            op = 0xC7
            op2 = 0x00
            User Status Flags: no change.
        - OR-AND-Not:
            op = 0xC7
            op2 = 0x03
            User Status Flags: no change.
        - OR-NOR:
            op = 0xC7
            op2 = 0x02
            User Status Flags: no change.
        - OR-OR:
            op = 0xC7
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'BIT_Acc_Logical_OR_Inst'
    op = "{0}{1}".format(bin(0xc)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11]))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_OR.AND.T"
        elif op2 == 0x3:
            self.name = "BIT_OR.ANDN.T"
        elif op2 == 0x2:
            self.name = "BIT_OR.NOR.T"
        elif op2 == 0x1:
            self.name = "BIT_OR.OR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        result = ""
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        if self.data['op2'] == 0x0:  # OR.AND.T
            result = (d_c & 0xfe) | ((d_c & 0x1) | (((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1)))

        elif self.data['op2'] == 0x3:  # OR.ANDN.T
            result = (d_c & 0xfe) | ((d_c & 0x1) | (((d_a >> pos1) & 0x1) & (((d_b >> pos2) & 0x1) ^ 0x1)))

        elif self.data['op2'] == 0x2:  # OR.NOR.T
            result = (d_c & 0xfe) | ((d_c & 0x1) | ((((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)) ^ 0x1))

        elif self.data['op2'] == 0x1:  # OR.OR.T
            result = (d_c & 0xfe) | ((d_c & 0x1) | (((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)))

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Acc_Shift_Inst_27(Instruction):
    """ Accumulating Bit Shift instructions.
        - Shift-AND:
            op = 0x27
            op2 = 0x00
            User Status Flags: no change.
        - Shift-AND-Not:
            op = 0x27
            op2 = 0x03
            User Status Flags: no change.
        - Shift-NOR:
            op = 0x27
            op2 = 0x02
            User Status Flags: no change.
        - Shift-OR:
            op = 0x27
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'BIT_Acc_Shift_Inst_27'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11]))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_SH.AND.T"
        elif op2 == 0x3:
            self.name = "BIT_SH.ANDN.T"
        elif op2 == 0x2:
            self.name = "BIT_SH.NOR.T"
        elif op2 == 0x1:
            self.name = "BIT_SH.OR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        result = ""
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        if self.data['op2'] == 0x0:  # SH.AND.T
            result = (d_c << 1) | (((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1))

        elif self.data['op2'] == 0x3:  # SH.ANDN.T
            result = (d_c << 1) | ((((d_a >> pos1) & 0x1) & (((d_b >> pos2) & 0x1) ^ 0x1)))

        elif self.data['op2'] == 0x2:  # SH.NOR.T
            result = (d_c << 1) | (((((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)) ^ 0x1))

        elif self.data['op2'] == 0x1:  # SH.OR.T
            result = (d_c << 1) | ((((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)))

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Acc_Shift_Inst_A7(Instruction):
    """ Accumulating Bit Shift instructions.
        - Shift-NAND:
            op = 0xA7
            op2 = 0x00
            User Status Flags: no change.
        - Shift-OR-Not:
            op = 0xA7
            op2 = 0x01
            User Status Flags: no change.
        - Shift-XNOR:
            op = 0xA7
            op2 = 0x02
            User Status Flags: no change.
        - Shift-XOR:
            op = 0xA7
            op2 = 0x03
            User Status Flags: no change.
    """
    name = 'BIT_Acc_Shift_Inst_A7'
    op = "{0}{1}".format(bin(0xa)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11]))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_SH.NAND.T"
        elif op2 == 0x1:
            self.name = "BIT_SH.ORN.T"
        elif op2 == 0x2:
            self.name = "BIT_SH.XNOR.T"
        elif op2 == 0x3:
            self.name = "BIT_SH.XOR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['c'])

    def get_d_c(self):
        return self.get("d{0}".format(self.data['c']), Type.int_32)

    def get_d_b(self):
        return self.get("d{0}".format(self.data['b']), Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return self.get_d_a(), self.get_d_b(), self.get_d_c()

    def compute_result(self, *args):
        d_a = args[0]
        d_b = args[1]
        d_c = args[2]
        result = ""
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        if self.data['op2'] == 0x0:  # SH.NAND.T
            result = (d_c << 1) | ((((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1)) ^ 0x1)

        elif self.data['op2'] == 0x1:  # OR.ORN.T
            result = (d_c << 1) | (((d_a >> pos1) & 0x1) | (((d_b >> pos2) & 0x1) ^ 0x1))

        elif self.data['op2'] == 0x2:  # OR.XNOR.T
            result = (d_c << 1) | ((((d_a >> pos1) & 0x1) ^ ((d_b >> pos2) & 0x1)) ^ 0x1)

        elif self.data['op2'] == 0x3:  # OR.XOR.T
            result = (d_c << 1) | (((d_a >> pos1) & 0x1) ^ ((d_b >> pos2) & 0x1))

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Logical_Inst(Instruction):
    """ BIT instructions.
        - Bit Logical AND:
            op = 0x87
            op2 = 0x00
            User Status Flags: no change.
        - Bit Logical AND-Not:
            op = 0x87
            op2 = 0x03
            User Status Flags: no change.
        - Bit Logical OR:
            op = 0x87
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'BIT_Logical_Inst'
    op = "{0}{1}".format(bin(8)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11]))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_AND.T"
        elif op2 == 0x3:
            self.name = "BIT_AND-Not"
        elif op2 == 0x1:
            self.name = "BIT_OR.T"
        elif op2 == 0x2:
            self.name = "BIT_NOR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

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
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        result = ""
        if self.data['op2'] == 0x0:  # BIT_AND.T
            result = ((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1)

        elif self.data['op2'] == 0x3:  # BIT_AND-Not
            result = ((d_a >> pos1) & 0x1) & ~((d_b >> pos2) & 0x1)

        elif self.data['op2'] == 0x1:  # BIT_OR.T
            result = ((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)

        elif self.data['op2'] == 0x2:  # BIT_NOR.T
            result = (((d_a >> pos1) & 0x1) | ((d_b >> pos2) & 0x1)) ^ 0x1

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Logical_07_Inst(Instruction):
    """ BIT Logical instructions with OP=07.
        - Bit Logical NAND:
            op = 0x07
            op2 = 0x00
            User Status Flags: no change.
        - OR-Not:
            op = 0x07
            op2 = 0x01
            User Status Flags: no change.
        - XNOR:
            op = 0x07
            op2 = 0x02
            User Status Flags: no change.
        - XOR:
            op = 0x07
            op2 = 0x03
            User Status Flags: no change.
    """
    name = 'BIT_Logical_07_Inst ...'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11].bin))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "BIT_NAND.T"
        elif op2 == 0x1:
            self.name = "BIT_ORN.T"
        elif op2 == 0x2:
            self.name = "BIT_XNOR.T"
        elif op2 == 0x3:
            self.name = "BIT_XOR.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

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
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        result = ""
        if self.data['op2'] == 0x0:  # NAND.T
            result = (((d_a >> pos1) & 0x1) & ((d_b >> pos2) & 0x1)) ^ 0x1

        elif self.data['op2'] == 0x1:  # ORN.T
            result = ((d_a >> pos1) & 0x1) | (~(d_b >> pos2) & 0x1)

        elif self.data['op2'] == 0x2:  # XNOR.T
            result = (((d_a >> pos1) & 0x1) ^ ((d_b >> pos2) & 0x1)) ^ 0x1

        elif self.data['op2'] == 0x3:  # XOR.T
            result = ((d_a >> pos1) & 0x1) ^ ((d_b >> pos2) & 0x1)

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class BIT_Mov_Inst(Instruction):
    """ BIT MOV instructions (op=67).
        - Insert Bit:
            op = 0x67
            op2 = 0x00
            User Status Flags: no change.
        - Insert Bit-Not:
            op = 0x67
            op2 = 0x01
            User Status Flags: no change.
    """
    name = 'BIT_Mov_Inst'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(7)[2:].zfill(4))
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
        b = tmp[16:20]
        pos1 = bitstring.BitArray(bin="{0}".format(tmp[11:16].bin.zfill(8)))
        op2 = bitstring.BitArray(bin="{0}".format(tmp[9:11].bin))
        op2 = int(op2.bin, 2)
        pos2 = bitstring.BitArray(bin="{0}".format(tmp[4:9].bin.zfill(8)))
        c = tmp[:4]

        if op2 == 0x0:
            self.name = "INS.T"
        elif op2 == 0x1:
            self.name = "INSN.T"
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.hex, 16),
                "b": int(b.hex, 16),
                "pos1": int(pos1.hex, 16),
                "op2": op2,
                "pos2": int(pos2.hex, 16),
                "c": int(c.hex, 16)}

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
        pos1 = self.data['pos1']
        pos2 = self.data['pos2']
        result = ""
        if self.data['op2'] == 0x0:  # INS.T
            result = d_a & ((((1 << 32) - 1) >> (pos1+1)) << (pos1+1))  # Set result[31:(pos_1+1)]=d_a[31:(pos_1+1)]
            bit_at_pos_2 = (d_b >> pos2) & 0x1                          # Read d_b[pos_2]
            result = result | (bit_at_pos_2 << pos1)                    # Write d_b[pos_2] to result[pos_1]
            result = result | (d_a & (1 << pos1) - 1)                   # Set result[(pos_1-1):0]=d_a[(pos_1-1):0]

        elif self.data['op2'] == 0x1:  # INSN.T
            result = d_a & ((((1 << 32) - 1) >> (pos1+1)) << (pos1+1))
            bit_at_pos_2 = ((d_b >> pos2) & 0x1) ^ 0x1
            result = result | (bit_at_pos_2 << pos1)
            result = result | (d_a & (1 << pos1) - 1)

        else:
            print("Error: Unknown OP2 '{0}' in {1}!".format(self.data['op2'], self.name))
            sys.exit(1)

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
