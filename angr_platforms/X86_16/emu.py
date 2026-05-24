from typing import Any, Dict

from .emulator import Emulator
from .instruction import InstrData, X86Instruction
from .regs import sgreg_t
from .stack_helpers import (
    pop_far_return_frame16,
    pop_far_return_frame32,
    pop_interrupt_frame16,
    pop_interrupt_frame32,
    push_far_return_frame16,
    push_far_return_frame32,
    push_privilege_stack32,
)


class EmuInstr(X86Instruction):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu, instr, mode32)

    def type_descriptor(self, instr: Dict[str, Any], sel: int) -> int:
        raise NotImplementedError

    def set_ldtr(self, sel: int) -> None:
        raise NotImplementedError

    def set_tr(self, sel: int) -> None:
        raise NotImplementedError

    def switch_task(self, sel: int) -> None:
        raise NotImplementedError

    def jmpf(self, instr: Dict[str, Any], sel: int, eip: int) -> None:
        self.emu.set_segment(sgreg_t.CS.name, sel)
        self.emu.set_eip(eip)

    def callf(self, instr: Dict[str, Any], sel: int, eip: int, return_ip=None) -> None:
        cs = self.emu.get_segment(sgreg_t.CS.name)
        RPL = sel & 3
        CPL = cs & 3

        if CPL != RPL:
            if RPL < CPL:
                raise Exception(self.emu.EXP_GP)
            push_privilege_stack32(self.emu)

        if self.mode32:
            push_far_return_frame32(self.emu, return_ip)
        else:
            push_far_return_frame16(self.emu, return_ip)

        self.emu.set_segment(sgreg_t.CS.name, sel)
        self.emu.set_eip(eip)

    def retf(self, instr: Dict[str, Any]) -> None:
        if self.mode32:
            eip, cs = pop_far_return_frame32(self.emu)
            self.emu.set_segment(sgreg_t.CS.name, cs)
            self.emu.set_eip(eip)
        else:
            ip, cs = pop_far_return_frame16(self.emu)
            self.emu.set_segment(sgreg_t.CS.name, cs)
            self.emu.set_ip(ip)

    def iret(self, instr: Dict[str, Any]) -> None:
        if self.mode32:
            eip, cs, flags = pop_interrupt_frame32(self.emu)
            self.emu.set_eflags(flags)
            self.emu.set_segment(sgreg_t.CS.name, cs)
            self.emu.set_eip(eip)
        else:
            ip, cs, flags = pop_interrupt_frame16(self.emu)
            self.emu.set_flags(flags)
            self.emu.set_segment(sgreg_t.CS.name, cs)
            self.emu.set_ip(ip)

    def chk_ring(self, dpl: int) -> bool:
        raise NotImplementedError
