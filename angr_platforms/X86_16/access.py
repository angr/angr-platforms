from pyvex.lifting.util.vex_helper import JumpKind, Type

from .hardware import Hardware
from .regs import reg16_t, reg32_t, sgreg_t

# Constants for access modes
MODE_READ = 0
MODE_WRITE = 1
MODE_EXEC = 2


class DataAccess(Hardware):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.tlb = []  # Translation Lookaside Buffer

    def set_segment(self, reg, sel):
        self.set_gpreg(reg, sel)

    def get_segment(self, reg):
        return self.lifter_instruction.get(reg.name.lower(), Type.int_16)

    def trans_v2p(self, mode, seg, vaddr):
        laddr = self.trans_v2l(mode, seg, vaddr)

        paddr = laddr
        return paddr

    def trans_v2l(self, mode, seg, vaddr):
        if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
            laddr = vaddr.cast_to(Type.int_16)  # Simplify ss: for decompiler
        else:
            if isinstance(seg, sgreg_t):
                sg = self.get_sgreg(seg)
            elif isinstance(seg, int):
                sg = self.constant(seg, Type.int_16)
            else:
                sg = seg
            if not isinstance(vaddr, int):
                vaddr = vaddr.cast_to(Type.int_32)
            laddr = (sg.cast_to(Type.int_32) << 4) + vaddr
        return laddr

    def search_tlb(self, vpn):
        if vpn + 1 > len(self.tlb) or self.tlb[vpn] is None:
            return None
        return self.tlb[vpn]

    def cache_tlb(self, vpn, pte):
        if vpn + 1 > len(self.tlb):
            self.tlb.extend([None] * (vpn + 1 - len(self.tlb)))
        self.tlb[vpn] = pte

    def push32(self, value):
        self.update_gpreg(reg32_t.ESP, -4)
        sp = self.get_gpreg(reg32_t.ESP)
        self.write_mem32_seg(sgreg_t.SS, sp, value)

    def pop32(self):
        sp = self.get_gpreg(reg32_t.ESP)
        value = self.read_mem32_seg(sgreg_t.SS, sp)
        self.update_gpreg(reg32_t.ESP, 4)
        return value

    def push16(self, value):
        self.update_gpreg(reg16_t.SP, -2)
        sp = self.get_gpreg(reg16_t.SP)
        self.write_mem16_seg(sgreg_t.SS, sp, value)

    def pop16(self):
        sp = self.get_gpreg(reg16_t.SP)
        value = self.read_mem16_seg(sgreg_t.SS, sp)
        self.update_gpreg(reg16_t.SP, 2)
        return value

    def read_mem32_seg(self, seg, addr):
        paddr = self.trans_v2p(MODE_READ, seg, addr)
        return self.read_mem32(paddr)
        io_base = self.chk_memio(paddr)
        return (
            self.read_memio32(io_base, paddr - io_base)
            if io_base
            else self.read_mem32(paddr)
        )

    def read_mem16_seg(self, seg, addr):
        paddr = self.trans_v2p(MODE_READ, seg, addr)
        return self.read_mem16(paddr)
        io_base = self.chk_memio(paddr)
        return (
            self.read_memio16(io_base, paddr - io_base)
            if io_base
            else self.read_mem16(paddr)
        )

    def read_mem8_seg(self, seg, addr):
        paddr = self.trans_v2p(MODE_READ, seg, addr)
        return self.read_mem8(paddr)
        io_base = self.chk_memio(paddr)
        return (
            self.read_memio8(io_base, paddr - io_base)
            if io_base
            else self.read_mem8(paddr)
        )

    def write_mem32_seg(self, seg, addr, value):
        paddr = self.trans_v2p(MODE_WRITE, seg, addr)
        self.write_mem32(paddr, value)
        return
        io_base = self.chk_memio(paddr)
        if io_base:
            self.write_memio32(io_base, paddr - io_base, value)
        else:
            self.write_mem32(paddr, value)

    def write_mem16_seg(self, seg, addr, value):
        paddr = self.trans_v2p(MODE_WRITE, seg, addr)
        self.write_mem16(paddr, value)
        return
        io_base = self.chk_memio(paddr)
        if io_base:
            self.write_memio16(io_base, paddr - io_base, value)
        else:
            self.write_mem16(paddr, value)

    def write_mem8_seg(self, seg, addr, value):
        paddr = self.trans_v2p(MODE_WRITE, seg, addr)
        self.write_mem8(paddr, value)
        return
        io_base = self.chk_memio(paddr)
        if io_base:
            self.write_memio8(io_base, paddr - io_base, value)
        else:
            self.write_mem8(paddr, value)

    def get_code8(self, offset):
        assert offset == 0
        return self.bitstream.read("uint:8")

    def get_code16(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:16")

    def get_code32(self, offset):
        assert offset == 0
        return self.bitstream.read("uintle:32")

    def get_data16(self, seg, addr):
        return self.read_mem16_seg(seg, addr)

    def get_data32(self, seg, addr):
        return self.read_mem32_seg(seg, addr)

    def get_data8(self, seg, addr):
        return self.read_mem8_seg(seg, addr)

    def put_data8(self, seg, addr, value):
        self.write_mem8_seg(seg, addr, value)

    def put_data16(self, seg, addr, value):
        self.write_mem16_seg(seg, addr, value)

    def put_data32(self, seg, addr, value):
        self.write_mem32_seg(seg, addr, value)

    def callf(self, seg, ip):
        self.push16(self.get_sgreg(sgreg_t.CS))
        self.push16(self.get_gpreg(reg16_t.IP) + 5)
        self.lifter_instruction.jump(None, self.trans_v2p(0, seg, ip), jumpkind=JumpKind.Call)
