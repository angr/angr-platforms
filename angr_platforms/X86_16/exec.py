import sys

from .addressing_helpers import (
    ResolvedMemoryOperand,
    resolve_linear_operand,
    resolve_modrm16_address,
    resolve_modrm32_address,
)
from .instruction import X86Instruction
from .regs import coerce_reg8_t, coerce_reg16_t, coerce_reg32_t, coerce_sgreg_t, reg8_t, reg16_t, reg32_t, sgreg_t


class ExecInstr(X86Instruction):
    def __init__(self, emu):
        self.instrfuncs = [None] * 0x200  # Initialize with None for all opcodes
        #self.chsz_ad = False

    def exec(self):
        opcode = self.instr.opcode

        if opcode >> 8 == 0x0f:
            opcode = (opcode & 0xff) | 0x0100

        if self.instrfuncs[opcode] is None:
            print(f"not implemented OPCODE 0x{opcode:02x}", file=sys.stderr)
            return False

        self.instrfuncs[opcode]()
        return True

    def set_rm32(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)


    def get_rm32(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg32_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_r32(self, value):
        self.emu.set_gpreg(coerce_reg32_t(self.instr.modrm.reg), value)

    def get_r32(self):
        return self.emu.get_gpreg(coerce_reg32_t(self.instr.modrm.reg))

    def set_moffs32(self, value):
        operand = self._resolved_moffs_operand(32)
        self.emu.put_data32(operand.segment, operand.offset, value)

    def get_moffs32(self):
        operand = self._resolved_moffs_operand(32)
        return self.emu.get_data32(operand.segment, operand.offset)

    def set_rm16(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg16_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_rm16(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg16_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_r16(self, value):
        self.emu.set_gpreg(coerce_reg16_t(self.instr.modrm.reg), value)

    def get_r16(self):
        return self.emu.get_gpreg(coerce_reg16_t(self.instr.modrm.reg))

    def set_moffs16(self, value):
        operand = self._resolved_moffs_operand(16)
        self.emu.put_data16(operand.segment, operand.offset, value)

    def get_moffs16(self):
        operand = self._resolved_moffs_operand(16)
        return self.emu.get_data16(operand.segment, operand.offset)

    def set_rm8(self, value):
        if self.instr.modrm.mod == 3:
            self.emu.set_gpreg(coerce_reg8_t(self.instr.modrm.rm), value)
            return
        operand = self._resolved_rm_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_rm8(self):
        if self.instr.modrm.mod == 3:
            return self.emu.get_gpreg(coerce_reg8_t(self.instr.modrm.rm))
        operand = self._resolved_rm_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def set_r8(self, value):
        self.emu.set_gpreg(coerce_reg8_t(self.instr.modrm.reg), value)

    def get_r8(self):
        return self.emu.get_gpreg(coerce_reg8_t(self.instr.modrm.reg))

    def set_moffs8(self, value):
        operand = self._resolved_moffs_operand(8)
        self.emu.put_data8(operand.segment, operand.offset, value)

    def get_moffs8(self):
        operand = self._resolved_moffs_operand(8)
        return self.emu.get_data8(operand.segment, operand.offset)

    def get_m(self):
        return self.calc_modrm()

    def _resolved_rm_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        seg, addr = self._resolved_rm_address()
        return resolve_linear_operand(
            self.emu,
            seg,
            addr,
            width_bits,
            self.effective_address_bits(),
        )

    def _resolved_rm_address(self):
        addr = self.calc_modrm()
        seg = self.select_segment()
        return seg, addr

    def _resolved_moffs_operand(self, width_bits: int) -> ResolvedMemoryOperand:
        self.instr.segment = sgreg_t.DS.value
        seg = self.select_segment()
        offset = self.instr.moffs
        return resolve_linear_operand(
            self.emu,
            seg,
            offset,
            width_bits,
            self.effective_address_bits(),
        )

    def set_sreg(self, value):
        self.emu.set_segment(coerce_sgreg_t(self.instr.modrm.reg), value)

    def get_sreg(self):
        return self.emu.get_segment(coerce_sgreg_t(self.instr.modrm.reg))

    def set_crn(self, value):
        print(f"set CR{self.instr.modrm.reg} = {value:x}")
        self.emu.set_crn(self.instr.modrm.reg, value)

    def get_crn(self):
        return self.emu.get_crn(self.instr.modrm.reg)

    def calc_modrm(self):
        assert self.instr.modrm.mod != 3

        self.instr.segment = sgreg_t.DS.value
        if self.effective_address_bits() == 32:
            return self.calc_modrm32()
        else:
            return self.calc_modrm16()

    def calc_modrm16(self):
        segment, addr = resolve_modrm16_address(self.emu, self.instr.modrm, self.instr.disp8, self.instr.disp16)
        self.instr.segment = segment.value
        return addr

    def calc_modrm32(self):
        segment, addr = resolve_modrm32_address(self.emu, self.instr.modrm, self.instr.sib, self.instr.disp8, self.instr.disp32)
        self.instr.segment = segment.value
        return addr
