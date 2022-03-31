#!/usr/bin/env python3
""" sys_instr.py
Implementation of SYS format instructions.
"""
from pyvex.lifting.util import Type, Instruction
from .logger import log_this


class SYS_DEBUG_Inst(Instruction):
    """ Debug instruction.
        op: 0x0D
        op2: 0x04
        User Status Flags: no change.
    """
    name = 'SYS_DEBUG'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2_1 = "{0}".format(bin(0)[2:].zfill(4))
    op2_2 = "{0}".format(bin(4)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*2 + op2_2 + 'd'*4 + 'c'*4 + op2_1 + 'e'*2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def compute_result(self, *args):
        # if DBGSR.DE == 0, execute NOP.
        pass

class SYS_ISYNC_Inst(Instruction):
    """ Synchronize Instructions instruction.
        op: 0x0D
        op2: 0x13
        User Status Flags: no change.
    """
    name = 'SYS_ISYNC'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2_1 = "{0}".format(bin(1)[2:].zfill(4))
    op2_2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*2 + op2_2 + 'd'*4 + 'c'*4 + op2_1 + 'e'*2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def compute_result(self, *args):
        # complete all previous instructions
        pass

class SYS_NOP_Inst(Instruction):
    """ No Operation instruction.
        op: 0x0d
        op2: 0x00
        User Status Flags: no change.
    """
    name = 'SYS_NOP'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0xd)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*2 + op2 + 'd'*4 + 'c'*4 + op2 + 'e'*2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def compute_result(self, *args):
        pass

class SYS_RSTV_Inst(Instruction):
    """ Reset Overflow Bits instruction.
        op: 0x2F
        op2: 0x00
        User Status Flags: clear V, SV, AV, SAV.
    """
    name = 'SYS_RSTV'
    op = "{0}{1}".format(bin(2)[2:].zfill(4), bin(0xf)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + 'b'*4 + 'a'*2 + op2 + 'd'*4 + 'c'*4 + op2 + 'e'*2

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def compute_result(self, *args):
        psw_val = self.get_psw()
        psw_val = (psw_val >> 31) << 31
        self.put(psw_val, "psw")
