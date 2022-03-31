#!/usr/bin/env python3
""" brn_instr.py
Implementation of BRN format instructions.
"""
import sys
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class BRN_Jump_Inst(Instruction):
    """ BRN Jump instructions:
          - Jump if Zero Bit instruction.
            op = 0x6F
            User Status Flags: no change.
          - Jump if Not Equal to Zero Bit instruction.
            op = 0x6F
            User Status Flags: no change.
    """
    name = 'BRN_Jump_Inst ...'
    op = "{0}{1}".format(bin(6)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        n_4 = tmp[24:]
        a = tmp[20:24]
        n = tmp[16:20]
        disp15 = tmp[1:16]
        op2 = int(tmp[:1].bin, 2)

        if op2 == 0:
            self.name = 'BRN_JZ.T'
        elif op2 == 1:
            self.name = 'BRN_JNZ.T'
        else:
            self.name = "UNKNOWN"

        data = {"a": int(a.bin, 2),
                "n": int(n.bin, 2),
                "n_4": n_4.bin,
                "disp15": int(disp15.bin, 2),
                "op2": op2}

        log_this(self.name, data, hex(self.addr))

        return data

    def get_disp15(self):
        return self.constant(self.data['disp15'], Type.int_15).cast_to(Type.int_32, signed=True)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def get_pc(self):
        return self.get("pc", Type.int_32)

    def fetch_operands(self):
        return [self.get_pc(), self.get_d_a(), self.get_disp15()]

    def compute_result(self, *args):
        pc = args[0]
        d_a = args[1]
        disp15 = args[2]
        if self.data["op2"] == 0:  # BRN_JZ.T
            cond = d_a[self.data['n']] == 0

        elif self.data["op2"] == 1:  # BRN_JNZ.T
            cond = d_a[self.data['n']] == 1

        else:
            print("Error: Unknown OP2 '{0}'".format(self.data['op2']))
            print("BRN instruction OP=6F, OP2=Unknown")
            sys.exit(1)

        dest = pc + (disp15 << 1)
        self.jump(cond, dest)
