from typing import Any, Dict

from .emulator import Emulator
from .instruction import InstrData, X86Instruction
from .regs import reg32_t, sgreg_t


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

    def callf(self, instr: Dict[str, Any], sel: int, eip: int) -> None:
        cs = self.emu.get_segment(sgreg_t.CS.name)
        RPL = sel & 3
        CPL = cs & 3

        if CPL != RPL:
            if RPL < CPL:
                raise Exception(self.emu.EXP_GP)
            self.emu.push32(self.emu.get_segment(sgreg_t.SS.name))
            self.emu.push32(self.emu.get_gpreg(reg32_t.ESP.name))

        self.emu.push32(cs)
        self.emu.push32(self.emu.get_eip())

        self.emu.set_segment(sgreg_t.CS.name, sel)
        self.emu.set_eip(eip)

    def retf(self, instr: Dict[str, Any]) -> None:
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        self.emu.set_segment(sgreg_t.CS.name, cs)
        self.emu.set_ip(ip)

    def iret(self, instr: Dict[str, Any]) -> None:
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        flags = self.emu.pop16()
        self.emu.set_flags(flags)
        self.emu.set_segment(sgreg_t.CS.name, cs)
        self.emu.set_ip(ip)

    def chk_ring(self, dpl: int) -> bool:
        raise NotImplementedError
