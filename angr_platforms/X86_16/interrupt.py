from collections import deque

from .access import DataAccess
from .debug import INFO
from .exception import EXCEPTION, EXP_GP
from .regs import sgreg_t

# Constants for descriptor table registers
IDTR = 1
TR = 3

class Interrupt(DataAccess):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        return
        self.intr_q = deque()  # Interrupt queue
        self.pic_m = None  # Master PIC
        self.pic_s = None  # Slave PIC

    def set_pic(self, pic, master):
        raise NotImplementedError

    def handle_interrupt(self):
        raise NotImplementedError
        if not self.intr_q:
            return

        n, hard = self.intr_q.popleft()

        idt_base = self.get_dtreg_base(IDTR)
        idt_limit = self.get_dtreg_limit(IDTR)
        idt_offset = n << 2

        EXCEPTION(EXP_GP, idt_offset > idt_limit)
        ivt = self.read_mem32(idt_base + idt_offset)

        cs = self.get_segment(sgreg_t.CS.name)
        self.set_segment(sgreg_t.CS.name, ivt >> 16)
        self.save_regs(False, cs)
        self.set_ip(ivt & 0xFFFF)

        INFO(4, "int 0x%02x (IP : 0x%04x, sgreg_t.CS.name : 0x%04x)", n, ivt & 0xFFFF, ivt >> 16)

    def chk_irq(self):
        raise NotImplementedError

    def save_regs(self, chpl, cs):
        self.push16(self.get_flags())
        self.push16(cs)
        self.push16(self.get_ip())
