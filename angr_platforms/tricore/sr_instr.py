#!/usr/bin/env python3
""" sr_instr.py
Implementation of SR format instructions.
"""
from pyvex.lifting.util import Type, Instruction, JumpKind
from .rtl import *  # pylint: disable=[wildcard-import, unused-wildcard-import]
from .logger import log_this


class SR_DEBUG_Inst(Instruction):
    """ Debug instruction.
        op: 0x00
        op2: 0x0A
        User Status Flags: no change.
    """
    name = 'SR_DEBUG'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0)[2:].zfill(4))
    op2 = "{0}".format(bin(0xa)[2:].zfill(4))
    bin_format = op + op2 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def compute_result(self, *args):
        # if DBGSR.DE == 0, execute NOP.
        pass

class SR_JI_Inst(Instruction):
    """ Jump Indirect instruction.
        op: 0xDC
        op2: 0x00
        User Status Flags: no change.
    """
    name = 'SR_JI'
    op = "{0}{1}".format(bin(0xd)[2:].zfill(4), bin(0xc)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + op2 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        data = {"a": int(data['a'], 2)}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_a_a(self):
        return self.get("a{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_a_a()]

    def compute_result(self, *args):
        a_a = args[0]
        dest = (a_a >> 1) << 1
        self.jump(None, dest)

class SR_NOP_Inst(Instruction):
    """ No Operation instruction.
        op: 0x00
        op2: 0x00
        User Status Flags: no change.
    """
    name = 'SR_NOP'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + op2 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

class SR_NOT_Inst(Instruction):
    """ Bitwise Complement NOT instruction.
        op: 0x46
        op2: 0x00
        User Status Flags: no change.
    """
    name = 'SR_NOT'
    op = "{0}{1}".format(bin(4)[2:].zfill(4), bin(6)[2:].zfill(4))
    op2 = "{0}".format(bin(0)[2:].zfill(4))
    bin_format = op + op2 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        a = int(data['a'], 2)
        data = {"a": a}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        return ~d_a

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SR_RET_Inst(Instruction):
    """ Return from Call instruction.
        op: 0x00
        op2: 0x09  (4-bits)
        User Status Flags: no change.
    """
    name = 'SR_RET'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0)[2:].zfill(4))
    op2 = "{0}".format(bin(9)[2:].zfill(4))
    bin_format = op + op2 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def get_a_11(self):
        return self.get("a11", Type.int_32)

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def fetch_operands(self):
        return self.get_psw(), self.get_a_11()

    def compute_result(self, *args):
        psw = args[0]
        a_11 = args[1]
        dest = (a_11 >> 1) << 1
        MASK_PCXI_PCXS = 0x000f0000
        MASK_PCXI_PCXO = 0x0000ffff
        pcxi = self.get("pcxi", Type.int_32)
        ea = ((pcxi & MASK_PCXI_PCXS) << 12) + ((pcxi & MASK_PCXI_PCXO) << 6)

        # restore context upper
        new_pcxi = self.load(ea, Type.int_32)
        #new_psw = self.load(ea+4, Type.int_32)  TODO
        self.put(psw, "psw")
        a10 = self.load(ea+8, Type.int_32)
        self.put(a10, "a10")
        a11 = self.load(ea+12, Type.int_32)
        self.put(a11, "a11")
        d8 = self.load(ea+16, Type.int_32)
        self.put(d8, "d8")
        d9 = self.load(ea+20, Type.int_32)
        self.put(d9, "d9")
        d10 = self.load(ea+24, Type.int_32)
        self.put(d10, "d10")
        d11 = self.load(ea+28, Type.int_32)
        self.put(d11, "d11")
        a12 = self.load(ea+32, Type.int_32)
        self.put(a12, "a12")
        a13 = self.load(ea+36, Type.int_32)
        self.put(a13, "a13")
        a14 = self.load(ea+40, Type.int_32)
        self.put(a14, "a14")
        a15 = self.load(ea+44, Type.int_32)
        self.put(a15, "a15")
        d12 = self.load(ea+48, Type.int_32)
        self.put(d12, "d12")
        d13 = self.load(ea+52, Type.int_32)
        self.put(d13, "d13")
        d14 = self.load(ea+56, Type.int_32)
        self.put(d14, "d14")
        d15 = self.load(ea+60, Type.int_32)
        self.put(d15, "d15")

        fcx = self.get("fcx", Type.int_32)
        self.store(fcx, ea)

        # FCX[19:0] = PCXI[19:0]
        fcx = (fcx >> 20) << 20 | (pcxi & 0xfffff)
        self.put(fcx, "fcx")

        self.put(new_pcxi, "pcxi")

        self.jump(None, dest, jumpkind=JumpKind.Ret)

class SR_RFE_Inst(Instruction):
    """ Return from Exception instruction.
        op: 0x00
        op2: 0x08  (4-bits)
        User Status Flags: no change.
    """
    name = 'SR_RFE'
    op = "{0}{1}".format(bin(0)[2:].zfill(4), bin(0)[2:].zfill(4))
    op2 = "{0}".format(bin(8)[2:].zfill(4))
    bin_format = op + op2 + 'i'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        log_this(self.name, data, hex(self.addr))
        return data

    def get_a11(self):
        return self.get("a11", Type.int_32)

    def fetch_operands(self):
        return [self.get_a11()]

    def compute_result(self, *args):
        a11 = args[0]
        # TODO: restore upper context register
        dest = (a11 >> 1) << 1
        self.jump(None, dest, jumpkind=JumpKind.Ret)

class SR_RSUB_Inst(Instruction):
    """ Reverse-Subtract instruction.
        op: 0x32
        op2: 0x05
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SR_RSUB'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(2)[2:].zfill(4))
    op2 = "{0}".format(bin(5)[2:].zfill(4))
    bin_format = op + op2 + 'a' * 4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        a = int(data['a'], 2)
        data = {"a": a}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_psw(self):
        return self.get("psw", Type.int_32)

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        result = (0 - d_a)

        # set flags
        c = 0
        v = overflow(result)
        av = advanced_overflow(result)
        psw = self.get_psw()
        cond_sv = (v == 0)
        cond_sav = (av == 0)
        sv = ((psw & SV_MASK) & cond_sv) | (1 & (cond_sv^1))
        sav = ((psw & ASV_MASK) & cond_sav) | (1 & (cond_sav^1))
        psw = set_usb(psw, c, v, sv, av, sav)
        self.put(psw, "psw")

        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())

class SR_SAT_HU_Inst(Instruction):
    """ Saturate Half-word Unsigned instruction.
        op: 0x32
        op2: 0x03
        User Status Flags: V, SV, AV, SAV.
    """
    name = 'SR_SAT.HU'
    op = "{0}{1}".format(bin(3)[2:].zfill(4), bin(2)[2:].zfill(4))
    op2 = "{0}".format(bin(3)[2:].zfill(4))
    bin_format = op + op2 + 'a'*4

    def parse(self, bitstrm):
        data = Instruction.parse(self, bitstrm)
        a = int(data['a'], 2)
        data = {"a": a}
        log_this(self.name, data, hex(self.addr))
        return data

    def get_dst_reg(self):
        return "d{0}".format(self.data['a'])

    def get_d_a(self):
        return self.get("d{0}".format(self.data['a']), Type.int_32)

    def fetch_operands(self):
        return [self.get_d_a()]

    def compute_result(self, *args):
        d_a = args[0]
        pos_cond = extend_to_32_bits(d_a > 0xffff)
        result = (0xffff & pos_cond) | d_a & (pos_cond^0xffffffff)
        return result

    def commit_result(self, res):
        self.put(res, self.get_dst_reg())
