#!/usr/bin/env python3
""" absb_instr.py
Implementation of ABSB format instructions.
"""
from pyvex.lifting.util import Type, Instruction
import bitstring
from .logger import log_this


class ABSB_ST_T_Inst(Instruction):
    """ Store Bit instruction:
        op = 0xD5
        op2 = 0x00  (2-bit)
        User Status Flags: no change.
    """
    name = 'ABSB_ST.T'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(5)[2:].zfill(4))
    bin_format = op + 'a'*4 + 'b'*4 + 'c'*4 + 'd'*4 + 'e'*4 + 'f'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        tmp = bitstring.BitArray(bin="{0}{1}{2}{3}{4}{5}".format(data['e'],
                                                                 data['f'],
                                                                 data['c'],
                                                                 data['d'],
                                                                 data['a'],
                                                                 data['b']))
        off18 = bitstring.BitArray(bin="{0}{1}{2}{3}".format(tmp[16:20].bin,
                                                             tmp[6:10].bin,
                                                             tmp[0:4].bin,
                                                             tmp[10:16].bin))
        #op2 = bitstring.BitArray(bin="{0}".format(tmp[4:6]))
        b = tmp[20:21]
        bpos = tmp[21:]

        data = {"b": int(b.bin, 2),
                "off18": int(off18.bin, 2),
                "bpos": int(bpos.bin, 2)}

        log_this(self.name, data, hex(self.addr))

        return data

    def compute_result(self, *args):
        off18 = self.data['off18']
        ea = "{0}00000000000000{1}".format(bin(off18 >> 14)[2:].zfill(4), bin(off18 & 0x3fff)[2:].zfill(14))
        ea_int = int(ea, 2)
        byte_pos = 0
        if (ea_int % 2) != 0:
            # align the memory address
            byte_pos = 4 - (ea_int % 2)
            ea_int = ea_int - byte_pos
            ea = self.constant(ea_int, Type.int_32)
        else:
            ea = self.constant(ea_int, Type.int_32)
        cur_val = self.load(ea, Type.int_32)
        modified_byte = (((cur_val >> (byte_pos*8)) & 0xff) & ~(1 << self.data["bpos"])) | \
                        (self.data['b'] << self.data["bpos"])
        changed_val = cur_val | (modified_byte << (byte_pos*8))
        self.store(changed_val, ea)
