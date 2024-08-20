
from pyvex.lifting.util import JumpKind, Type

from .instr_base import InstrBase
from .instruction import *
from .regs import reg8_t, reg16_t, sgreg_t


class Instr16(InstrBase):
    def __init__(self, emu: Emulator, instr: InstrData):
        super().__init__(emu, instr, mode32=False)  # X86Instruction

        self.set_funcflag(0x01, self.add_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x03, self.add_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x05, self.add_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x06, self.push_es, 0)
        self.set_funcflag(0x07, self.pop_es, 0)
        self.set_funcflag(0x09, self.or_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x0B, self.or_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0D, self.or_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x0E, self.push_cs, 0)
        self.set_funcflag(0x11, self.adc_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x13, self.adc_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x16, self.push_ss, 0)
        self.set_funcflag(0x17, self.pop_ss, 0)
        self.set_funcflag(0x19, self.sbb_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x1B, self.sbb_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x1E, self.push_ds, 0)
        self.set_funcflag(0x1F, self.pop_ds, 0)
        self.set_funcflag(0x21, self.and_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x23, self.and_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x25, self.and_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x29, self.sub_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x2B, self.sub_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x2D, self.sub_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x31, self.xor_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x33, self.xor_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x35, self.xor_ax_imm16, CHK_IMM16)
        self.set_funcflag(0x39, self.cmp_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x3B, self.cmp_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x3D, self.cmp_ax_imm16, CHK_IMM16)

        for i in range(8):
            self.set_funcflag(0x40+i, self.inc_r16, 0)
            self.set_funcflag(0x48+i, self.dec_r16, 0)
            self.set_funcflag(0x50+i, self.push_r16, 0)
            self.set_funcflag(0x58+i, self.pop_r16, 0)

        self.set_funcflag(0x60, self.pusha, 0)
        self.set_funcflag(0x61, self.popa, 0)
        self.set_funcflag(0x68, self.push_imm16, CHK_IMM16)
        self.set_funcflag(0x69, self.imul_r16_rm16_imm16, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0x6A, self.push_imm8, CHK_IMM8)
        self.set_funcflag(0x6B, self.imul_r16_rm16_imm8, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0x85, self.test_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x87, self.xchg_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x89, self.mov_rm16_r16, CHK_MODRM)
        self.set_funcflag(0x8B, self.mov_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x8C, self.mov_rm16_sreg, CHK_MODRM)
        self.set_funcflag(0x8D, self.lea_r16_m16, CHK_MODRM)

        for i in range(1, 8):
            self.set_funcflag(0x90+i, self.xchg_r16_ax, 0)

        self.set_funcflag(0x98, self.cbw, 0)
        self.set_funcflag(0x99, self.cwd, 0)
        self.set_funcflag(0x9A, self.callf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        self.set_funcflag(0x9C, self.pushf, 0)
        self.set_funcflag(0x9D, self.popf, 0)
        self.set_funcflag(0xA1, self.mov_ax_moffs16, CHK_MOFFS)
        self.set_funcflag(0xA3, self.mov_moffs16_ax, CHK_MOFFS)
        self.set_funcflag(0xA5, self.movsw_m16_m16, 0)
        self.set_funcflag(0xA6, self.cmps_m8_m8, 0)
        self.set_funcflag(0xA7, self.cmps_m16_m16, 0)
        self.set_funcflag(0xA9, self.test_ax_imm16, CHK_IMM16)

        for i in range(8):
            self.set_funcflag(0xB8+i, self.mov_r16_imm16, CHK_IMM16)

        self.set_funcflag(0xC3, self.ret, 0)
        self.set_funcflag(0xC4, self.les_es_r16_m16, CHK_MODRM)
        self.set_funcflag(0xC7, self.mov_rm16_imm16, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0xC8, self.enter, CHK_IMM16 | CHK_IMM8)
        self.set_funcflag(0xC9, self.leave, 0)
        self.set_funcflag(0xE0, self.loop16ne, CHK_IMM8)
        self.set_funcflag(0xE1, self.loop16e, CHK_IMM8)
        self.set_funcflag(0xE2, self.loop16, CHK_IMM8)
        self.set_funcflag(0xE3, self.jcxz_rel8, CHK_IMM8)
        self.set_funcflag(0xE5, self.in_ax_imm8, CHK_IMM8)
        self.set_funcflag(0xE7, self.out_imm8_ax, CHK_IMM8)
        self.set_funcflag(0xE8, self.call_rel16, CHK_IMM16)
        self.set_funcflag(0xE9, self.jmp_rel16, CHK_IMM16)
        self.set_funcflag(0xEA, self.jmpf_ptr16_16, CHK_PTR16 | CHK_IMM16)
        self.set_funcflag(0xED, self.in_ax_dx, 0)
        self.set_funcflag(0xEF, self.out_dx_ax, 0)

        self.set_funcflag(0x0F80, self.jo_rel16, CHK_IMM16)
        self.set_funcflag(0x0F81, self.jno_rel16, CHK_IMM16)
        self.set_funcflag(0x0F82, self.jb_rel16, CHK_IMM16)
        self.set_funcflag(0x0F83, self.jnb_rel16, CHK_IMM16)
        self.set_funcflag(0x0F84, self.jz_rel16, CHK_IMM16)
        self.set_funcflag(0x0F85, self.jnz_rel16, CHK_IMM16)
        self.set_funcflag(0x0F86, self.jbe_rel16, CHK_IMM16)
        self.set_funcflag(0x0F87, self.ja_rel16, CHK_IMM16)
        self.set_funcflag(0x0F88, self.js_rel16, CHK_IMM16)
        self.set_funcflag(0x0F89, self.jns_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8A, self.jp_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8B, self.jnp_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8C, self.jl_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8D, self.jnl_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8E, self.jle_rel16, CHK_IMM16)
        self.set_funcflag(0x0F8F, self.jnle_rel16, CHK_IMM16)
        self.set_funcflag(0x0FAF, self.imul_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0FB6, self.movzx_r16_rm8, CHK_MODRM)
        self.set_funcflag(0x0FB7, self.movzx_r16_rm16, CHK_MODRM)
        self.set_funcflag(0x0FBE, self.movsx_r16_rm8, CHK_MODRM)
        self.set_funcflag(0x0FBF, self.movsx_r16_rm16, CHK_MODRM)

        self.set_funcflag(0x81, self.code_81, CHK_MODRM | CHK_IMM16)
        self.set_funcflag(0x83, self.code_83, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xC1, self.code_c1, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xD1, self.code_d1, CHK_MODRM)
        self.set_funcflag(0xD3, self.code_d3, CHK_MODRM)
        self.set_funcflag(0xF7, self.code_f7, CHK_MODRM)
        self.set_funcflag(0xFF, self.code_ff, CHK_MODRM)
        self.set_funcflag(0x0F00, self.code_0f00, CHK_MODRM)
        self.set_funcflag(0x0F01, self.code_0f01, CHK_MODRM)


    def jcxz_rel8(self) -> None:
        cx = self.emu.get_gpreg(reg16_t.CX)
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not (cx == 0), ip)


    def loop16(self) -> None:
        cx = self.emu.get_gpreg(reg16_t.CX)
        cx -= 1
        self.emu.set_gpreg(reg16_t.CX, cx)
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8, Type.int_8).signed + 2
        self.emu.lifter_instruction.jump(cx != 0, ip, JumpKind.Boring)

    def loop16e(self) -> None:
        cx = self.emu.get_gpreg(reg16_t.CX)
        cx -= 1
        self.emu.set_gpreg(reg16_t.CX, cx)
        zero = self.emu.is_zero()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8, Type.int_8).signed + 2
        self.emu.lifter_instruction.jump(cx and zero, ip, JumpKind.Boring)

    def loop16ne(self) -> None:
        cx = self.emu.get_gpreg(reg16_t.CX)
        cx -= 1
        self.emu.set_gpreg(reg16_t.CX, cx)
        zero = self.emu.is_zero()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8, Type.int_8).signed + 2
        self.emu.lifter_instruction.jump(cx and not zero, ip, JumpKind.Boring)

    def sbb_r16_rm16(self) -> None:
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        carry = self.emu.is_carry().cast_to(Type.int_16)
        self.set_r16(r16 - rm16 - carry)
        self.emu.update_eflags_sbb(r16, rm16, carry)

    def add_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.set_rm16(rm16 + r16)
        self.emu.update_eflags_add(rm16, r16)

    def sbb_rm16_r16(self) -> None:
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        carry = self.emu.is_carry().cast_to(Type.int_16)
        self.set_rm8(rm16 - r16 - carry)
        self.emu.update_eflags_sbb(rm16, r16, carry)

    def adc_rm16_r16(self) -> None:
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        carry = self.emu.is_carry().cast_to(Type.int_16)
        self.set_rm8(rm16 + r16 + carry)
        self.emu.update_eflags_adc(rm16, r16, carry)

    def add_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(r16 + rm16)
        self.emu.update_eflags_add(r16, rm16)

    def adc_r16_rm16(self) -> None:
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        carry = self.emu.is_carry().cast_to(Type.int_16)
        self.set_r16(r16 + rm16 + carry)
        self.emu.update_eflags_adc(r16, rm16, carry)

    def add_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, ax + self.instr.imm16)
        self.emu.update_eflags_add(ax, self.instr.imm16)

    def push_es(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.ES))

    def pop_es(self):
        self.emu.set_segment(sgreg_t.ES, self.emu.pop16())

    def or_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.set_rm16(rm16 | r16)
        self.emu.update_eflags_or(rm16, r16)

    def or_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(r16 | rm16)
        self.emu.update_eflags_or(r16, rm16)

    def or_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, ax | self.instr.imm16)
        self.emu.update_eflags_or(ax, self.instr.imm16)

    def push_cs(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.CS))

    def push_ss(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.SS))

    def pop_ss(self):
        self.emu.set_segment(sgreg_t.SS, self.emu.pop16())

    def push_ds(self):
        self.emu.push16(self.emu.get_segment(sgreg_t.DS))

    def pop_ds(self):
        self.emu.set_segment(sgreg_t.DS, self.emu.pop16())

    def and_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.set_rm16(rm16 & r16)
        self.emu.update_eflags_and(rm16, r16)

    def and_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(r16 & rm16)
        self.emu.update_eflags_and(r16, rm16)

    def and_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, ax & self.instr.imm16)
        self.emu.update_eflags_and(ax, self.instr.imm16)

    def sub_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.set_rm16(rm16 - r16)
        self.emu.update_eflags_sub(rm16, r16)

    def sub_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(r16 - rm16)
        self.emu.update_eflags_sub(r16, rm16)

    def sub_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, ax - self.instr.imm16)
        self.emu.update_eflags_sub(ax, self.instr.imm16)

    def xor_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.set_rm16(rm16 ^ r16)
        self.emu.update_eflags_xor(rm16, r16)


    def xor_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(r16 ^ rm16)
        self.emu.update_eflags_xor(rm16, r16)

    def xor_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, ax ^ self.instr.imm16)
        self.emu.update_eflags_xor(ax, self.instr.imm16)

    def cmp_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.emu.update_eflags_sub(rm16, r16)

    def cmp_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.emu.update_eflags_sub(r16, rm16)

    def cmp_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.update_eflags_sub(ax, self.instr.imm16)

    def inc_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        r16 = self.emu.get_gpreg(reg) + 1
        self.emu.set_gpreg(reg, r16)
        self.emu.update_eflags_inc(r16)

    def dec_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        r16 = self.emu.get_gpreg(reg)
        self.emu.set_gpreg(reg, r16 - 1)
        self.emu.update_eflags_dec(r16)

    def push_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        self.emu.push16(self.emu.get_gpreg(reg))

    def pop_r16(self):
        reg = reg16_t(self.instr.opcode & 0b111)
        self.emu.set_gpreg(reg, self.emu.pop16())

    def pusha(self):
        sp = self.emu.get_gpreg(reg16_t.SP)
        self.emu.push16(self.emu.get_gpreg(reg16_t.AX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.CX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.DX))
        self.emu.push16(self.emu.get_gpreg(reg16_t.BX))
        self.emu.push16(sp)
        self.emu.push16(self.emu.get_gpreg(reg16_t.BP))
        self.emu.push16(self.emu.get_gpreg(reg16_t.SI))
        self.emu.push16(self.emu.get_gpreg(reg16_t.DI))

    def popa(self):
        self.emu.set_gpreg(reg16_t.DI, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.SI, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.BP, self.emu.pop16())
        sp = self.emu.pop16()
        self.emu.set_gpreg(reg16_t.BX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.DX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.CX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.AX, self.emu.pop16())
        self.emu.set_gpreg(reg16_t.SP, sp)

    def push_imm16(self):
        self.emu.push16(self.emu.constant(self.instr.imm16, Type.int_16))

    def imul_r16_rm16_imm16(self):
        rm16_s = self.get_rm16()
        self.set_r16(rm16_s * self.instr.imm16)
        self.emu.update_eflags_imul(rm16_s, self.instr.imm16)

    def push_imm8(self):
        self.emu.push16(self.instr.imm8)

    def imul_r16_rm16_imm8(self):
        rm16_s = self.get_rm16()
        self.set_r16(rm16_s * self.instr.imm8)
        self.emu.update_eflags_imul(rm16_s, self.instr.imm8)

    def test_rm16_r16(self):
        rm16 = self.get_rm16()
        r16 = self.get_r16()
        self.emu.update_eflags_and(rm16, r16)

    def xchg_r16_rm16(self):
        r16 = self.get_r16()
        rm16 = self.get_rm16()
        self.set_r16(rm16)
        self.set_rm16(r16)

    def mov_rm16_r16(self):
        r16 = self.get_r16()
        self.set_rm16(r16)

    def mov_r16_rm16(self):
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def mov_rm16_sreg(self):
        sreg = self.get_sreg()
        self.set_rm16(sreg)

    def lea_r16_m16(self):
        m16 = self.get_m()
        self.set_r16(m16)

    def les_es_r16_m16(self):
        m16 = self.get_m()
        self.set_r16(m16)

    def xchg_r16_ax(self):
        reg = self.instr.opcode & 0b111
        r16 = self.emu.get_gpreg(reg16_t(reg))
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t(reg), ax)
        self.emu.set_gpreg(reg16_t.AX, r16)

    def cbw(self):
        al_s = self.emu.get_gpreg(reg8_t.AL).widen_signed(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, al_s)

    def cwd(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.DX, -1 if ax & 0x8000 else 0)

    def callf_ptr16_16(self):
        self.emu.callf(self.instr.ptr16, self.instr.imm16)


    def pushf(self):
        self.emu.push16(self.emu.get_flags())

    def popf(self):
        self.emu.set_flags(self.emu.pop16())

    def mov_ax_moffs16(self):
        self.emu.set_gpreg(reg16_t.AX, self.get_moffs16())

    def mov_moffs16_ax(self):
        self.set_moffs16(self.emu.get_gpreg(reg16_t.AX))

    def cmps_m8_m8(self):
        while True:
            m8_s = self.emu.get_data8(sgreg_t(self.instr.segment), self.emu.get_gpreg(reg16_t.SI))
            m8_d = self.emu.get_data8(self.emu.ES, self.emu.get_gpreg(reg16_t.DI))
            self.emu.update_eflags_sub(m8_s, m8_d)

            self.emu.update_gpreg(reg16_t.SI, -1 if self.emu.is_direction() else 1)
            self.emu.update_gpreg(reg16_t.DI, -1 if self.emu.is_direction() else 1)

            if self.instr.pre_repeat != self.emu.NONE:
                self.emu.update_gpreg(reg16_t.CX, -1)
                if self.instr.pre_repeat == self.emu.REPZ:
                    if not self.emu.get_gpreg(reg16_t.CX) or not self.emu.is_zero():
                        break
                elif self.instr.pre_repeat == self.emu.REPNZ:
                    if not self.emu.get_gpreg(reg16_t.CX) or self.emu.is_zero():
                        break
            else:
                break

    def cmps_m16_m16(self):
        while True:
            m16_s = self.emu.get_data16(sgreg_t(self.instr.segment), self.emu.get_gpreg(reg16_t.SI))
            m16_d = self.emu.get_data16(reg16_t.ES, self.emu.get_gpreg(reg16_t.DI))
            self.emu.update_eflags_sub(m16_s, m16_d)

            self.emu.update_gpreg(reg16_t.SI, -2 if self.emu.is_direction() else 2)
            self.emu.update_gpreg(reg16_t.DI, -2 if self.emu.is_direction() else 2)

            if self.instr.pre_repeat != self.emu.NONE:
                self.emu.update_gpreg(reg16_t.CX, -1)
                if self.instr["pre_               repeat"] == self.emu.REPZ:
                    if not self.emu.get_gpreg(reg16_t.CX) or not self.emu.is_zero():
                        break
                elif self.instr.pre_repeat == self.emu.REPNZ:
                    if not self.emu.get_gpreg(reg16_t.CX) or self.emu.is_zero():
                        break
            else:
                break


    def movsw_m16_m16(self):
        if self.instr.pre_repeat != NONE:
            self.emu.update_gpreg(reg16_t.CX, -1)
            ip = self.emu.get_gpreg(reg16_t.IP)
            if self.instr.pre_repeat == REPZ:
                self.emu.lifter_instruction.jump(self.emu.get_gpreg(reg16_t.CX) == 0, ip, JumpKind.Boring)
            elif self.instr.pre_repeat == REPNZ:
                self.emu.lifter_instruction.jump(self.emu.get_gpreg(reg16_t.CX) != 0, ip, JumpKind.Boring)

        m16_s = self.emu.get_data16(sgreg_t(self.instr.segment), self.emu.get_gpreg(reg16_t.SI))
        self.emu.put_data16(sgreg_t.ES, self.emu.get_gpreg(reg16_t.DI), m16_s)

        self.emu.update_gpreg(reg16_t.SI, 2 if ~self.emu.is_direction() else -2)
        self.emu.update_gpreg(reg16_t.DI, 2 if ~self.emu.is_direction() else -2)


    def test_ax_imm16(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.update_eflags_and(ax, self.instr.imm16)

    def mov_r16_imm16(self):
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(reg16_t(reg), self.instr.imm16)

    def ret(self):
        ip = self.emu.pop16()
        self.emu.lifter_instruction.jump(None, ip, jumpkind=JumpKind.Ret)

    def mov_rm16_imm16(self):
        self.set_rm16(self.emu.constant(self.instr.imm16, Type.int_16))

    def leave(self):
        ebp = self.emu.get_gpreg(reg16_t.BP)
        self.emu.set_gpreg(reg16_t.SP, ebp)
        self.emu.set_gpreg(reg16_t.BP, self.emu.pop16())

    def in_ax_imm8(self):
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(self.instr.imm8))

    def out_imm8_ax(self):
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(self.instr.imm8, ax)

    def call_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP)
        self.emu.push16(ip + 3)
        self.emu.lifter_instruction.jump(None, ip + self.emu.constant(self.instr.imm16, Type.int_16).signed + 3, jumpkind=JumpKind.Call)


    def jmp_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 3
        self.emu.lifter_instruction.jump(None, ip, JumpKind.Boring)

    def jmpf_ptr16_16(self):
        self.emu.jmpf(self.instr.ptr16, self.instr.imm16)

    def in_ax_dx(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg16_t.AX, self.emu.in_io16(dx))

    def out_dx_ax(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.out_io16(dx, ax)

    def jo_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not self.emu.is_overflow(), ip)

    def jno_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_overflow(), ip)

    def jb_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not self.emu.is_carry(), ip)

    def jnb_rel16(self):  # jae, jnc
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_carry(), ip)

    def jz_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not self.emu.is_zero(), ip)

    def jnz_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_zero(), ip)

    def jbe_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not (self.emu.is_carry() or self.emu.is_zero()), ip)

    def ja_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_carry() or self.emu.is_zero(), ip)

    def js_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not self.emu.is_sign(), ip)

    def jns_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_sign(), ip)

    def jp_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not self.emu.is_parity(), ip)

    def jnp_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_parity(), ip)

    def jl_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not (self.emu.is_sign() != self.emu.is_overflow()), ip)

    def jnl_rel16(self):  # jge
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_sign() != self.emu.is_overflow(), ip)

    def jle_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(not (self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow())), ip)

    def jnle_rel16(self):
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm16, Type.int_16).signed + 4
        self.emu.lifter_instruction.jump(self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow()),
                                         ip)

    def imul_r16_rm16(self):
        r16_s = self.get_r16()
        rm16_s = self.get_rm16()
        self.set_r16(r16_s * rm16_s)
        self.emu.update_eflags_imul(r16_s, rm16_s)

    def movzx_r16_rm8(self):
        rm8 = self.emu.get_data8(sgreg_t(self.instr.segment), self.calc_modrm())
        self.set_r16(rm8)

    def movzx_r16_rm16(self):
        rm16 = self.get_rm16()
        self.set_r16(rm16)

    def movsx_r16_rm8(self):
        rm8_s = self.emu.get_data8(sgreg_t(self.instr.segment), self.calc_modrm()).widen_signed(Type.int_16)
        self.set_r16(rm8_s)

    def movsx_r16_rm16(self):
        rm16_s = self.get_rm16().signed  # TODO source is 16 bit??
        self.set_r16(rm16_s)

    def code_81(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.add_rm16_imm16()
        elif reg == 1:
            self.or_rm16_imm16()
        elif reg == 2:
            self.adc_rm16_imm16()
        elif reg == 3:
            self.sbb_rm16_imm16()
        elif reg == 4:
            self.and_rm16_imm16()
        elif reg == 5:
            self.sub_rm16_imm16()
        elif reg == 6:
            self.xor_rm16_imm16()
        elif reg == 7:
            self.cmp_rm16_imm16()
        else:
            raise RuntimeError(f"not implemented: 0x81 /{reg}")

    def code_83(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.add_rm16_imm8()
        elif reg == 1:
            self.or_rm16_imm8()
        elif reg == 2:
            self.adc_rm16_imm8()
        elif reg == 3:
            self.sbb_rm16_imm8()
        elif reg == 4:
            self.and_rm16_imm8()
        elif reg == 5:
            self.sub_rm16_imm8()
        elif reg == 6:
            self.xor_rm16_imm8()
        elif reg == 7:
            self.cmp_rm16_imm8()
        else:
            raise RuntimeError(f"not implemented: 0x83 /{reg}")

    def code_c1(self):
        reg = self.instr.modrm.reg
        if reg == 4:
            self.shl_rm16_imm8()
        elif reg == 5:
            self.shr_rm16_imm8()
        elif reg == 6:
            self.sal_rm16_imm8()
        elif reg == 7:
            self.sar_rm16_imm8()
        else:
            raise RuntimeError(f"not implemented: 0xc1 /{reg}")

    def code_d1(self):
        reg = self.instr.modrm.reg
        if reg == 4:
            self.shl_rm16_1()
        elif reg == 5:
            self.shr_rm16_1()
        elif reg == 6:
            self.sal_rm16_1()
        elif reg == 7:
            self.sar_rm16_1()
        else:
            raise RuntimeError(f"not implemented: 0xd1 /{reg}")

    def code_d3(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.rol_rm16_cl()
        elif reg == 4:
            self.shl_rm16_cl()
        elif reg == 5:
            self.shr_rm16_cl()
        elif reg == 6:
            self.sal_rm16_cl()
        elif reg == 7:
            self.sar_rm16_cl()
        else:
            raise RuntimeError(f"not implemented: 0xd3 /{reg}")

    def code_f7(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.test_rm16_imm16()
        elif reg == 2:
            self.not_rm16()
        elif reg == 3:
            self.neg_rm16()
        elif reg == 4:
            self.mul_dx_ax_rm16()
        elif reg == 5:
            self.imul_dx_ax_rm16()
        elif reg == 6:
            self.div_dx_ax_rm16()
        elif reg == 7:
            self.idiv_dx_ax_rm16()
        else:
            raise RuntimeError(f"not implemented: 0xf7 /{reg}")

    def code_ff(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.inc_rm16()
        elif reg == 1:
            self.dec_rm16()
        elif reg == 2:
            self.call_rm16()
        elif reg == 3:
            self.callf_m16_16()
        elif reg == 4:
            self.jmp_rm16()
        elif reg == 5:
            self.jmpf_m16_16()
        elif reg == 6:
            self.push_rm16()
        else:
            raise RuntimeError(f"not implemented: 0xff /{reg}")

    def code_0f00(self):
        reg = self.instr.modrm.reg
        if reg == 3:
            self.ltr_rm16()
        else:
            raise RuntimeError(f"not implemented: 0x0f00 /{reg}")

    def code_0f01(self):
        reg = self.instr.modrm.reg
        #if reg == 2:
        #    self.lgdt_m24()
        #elif reg == 3:
        #    self.lidt_m24()
        #else:
        raise RuntimeError(f"not implemented: 0x0f01 /{reg}")

    def add_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 + self.instr.imm16)
        self.emu.update_eflags_add(rm16, self.instr.imm16)

    def or_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 | self.instr.imm16)
        self.emu.update_eflags_or(rm16, self.instr.imm16)

    def adc_rm16_imm16(self):
        rm16 = self.get_rm16()
        cf = self.emu.is_carry()
        self.set_rm16(rm16 + self.instr.imm16 + cf)
        self.emu.update_eflags_add(rm16, self.instr.imm16 + cf)

    def sbb_rm16_imm16(self):
        rm16 = self.get_rm16()
        cf = self.emu.is_carry()
        self.set_rm16(rm16 - self.instr.imm16 - cf)
        self.emu.update_eflags_sbb(rm16, self.instr.imm16, cf)

    def and_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 & self.instr.imm16)
        self.emu.update_eflags_and(rm16, self.instr.imm16)

    def sub_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 - self.instr.imm16)
        self.emu.update_eflags_sub(rm16, self.instr.imm16)

    def xor_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 ^ self.instr.imm16)

    def cmp_rm16_imm16(self):
        rm16 = self.get_rm16()
        self.emu.update_eflags_sub(rm16, self.instr.imm16)

    def add_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 + self.instr.imm8)
        self.emu.update_eflags_add(rm16, self.instr.imm8)

    def or_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 | self.instr.imm8)
        self.emu.update_eflags_or(rm16, self.instr.imm8)

    def adc_rm16_imm8(self):
        rm16 = self.get_rm16()
        cf = self.emu.is_carry()
        self.set_rm16(rm16 + self.instr.imm8 + cf)
        self.emu.update_eflags_add(rm16, self.instr.imm8 + cf)

    def sbb_rm16_imm8(self):
        rm16 = self.get_rm16()
        cf = self.emu.is_carry()
        self.set_rm16(rm16 - self.instr.imm8 - cf)
        self.emu.update_eflags_sbb(rm16, self.instr.imm8, cf)

    def and_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 & self.instr.imm8)
        self.emu.update_eflags_and(rm16, self.emu.constant(self.instr.imm8, Type.int_16))

    def sub_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 - self.instr.imm8)
        self.emu.update_eflags_sub(rm16, self.emu.constant(self.instr.imm8, Type.int_16))

    def xor_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 ^ self.instr.imm8)

    def cmp_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.emu.update_eflags_sub(rm16, self.instr.imm8)

    def shl_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.shl(rm16, self.instr.imm8)

    def shr_rm16_imm8(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 >> self.instr.imm8)
        self.emu.update_eflags_shr(rm16, self.instr.imm8)

    def sal_rm16_imm8(self):
        rm16_s = self.get_rm16().signed
        self.set_rm16(rm16_s << self.instr.imm8)

    def sar_rm16_imm8(self):
        rm16_s = self.get_rm16().signed
        self.set_rm16(rm16_s.sar(self.instr.imm8))

    def shl_rm16_1(self):
        rm16 = self.get_rm16()
        cl = self.emu.constant(1, Type.int_8)
        self.shl(rm16, cl)

    def rol_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.rol(rm16, cl)

    def rol(self, a, b):
        self.set_rm16(a.rol(b))
        self.emu.update_eflags_shl(a, b)

    def shl_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shl(rm16, cl)

    def shl(self, a, b):
        self.set_rm16(a << b)
        self.emu.update_eflags_shl(a, b)

    def shr_rm16_cl(self):
        rm16 = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.shr(rm16, cl)

    def shr_rm16_1(self):
        rm16 = self.get_rm16()
        cl = self.emu.constant(1, Type.int_8)
        self.shr(rm16, cl)

    def shr(self, a, b):
        self.set_rm16(a >> b)
        self.emu.update_eflags_shr(a, b)

    def sal_rm16_1(self):
        rm16_s = self.get_rm16().signed
        cl = self.emu.constant(1, Type.int_8)
        self.set_rm16(rm16_s << cl)

    def sar_rm16_1(self):
        rm16_s = self.get_rm16()
        cl = self.emu.constant(1, Type.int_8)
        self.set_rm16(rm16_s.sar(cl))

    def sal_rm16_cl(self):
        rm16_s = self.get_rm16().signed
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm16(rm16_s << cl)

    def sar_rm16_cl(self):
        rm16_s = self.get_rm16()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm16(rm16_s.sar(cl))

    def test_rm16_imm16(self):
        rm16 = self.get_rm16()
        imm16 = self.instr.modrm.imm16  # self.emu.get_code16(0)
        #self.emu.update_eip(2)
        self.emu.update_eflags_and(rm16, imm16)

    def not_rm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(~rm16)

    def neg_rm16(self):
        rm16_s = self.get_rm16().signed
        self.set_rm16((rm16_s * -1).cast_to(Type.int_16))
        self.emu.update_eflags_neg(rm16_s)

    def mul_dx_ax_rm16(self):
        rm16 = self.get_rm16()
        ax = self.emu.get_gpreg(reg16_t.AX)
        val = ax * rm16
        self.emu.set_gpreg(reg16_t.AX, val & 0xFFFF)
        self.emu.set_gpreg(reg16_t.DX, (val >> 16) & 0xFFFF)
        self.emu.update_eflags_mul(ax, rm16)

    def imul_dx_ax_rm16(self):
        rm16_s = self.get_rm16().signed
        ax_s = self.emu.get_gpreg(reg16_t.AX).signed
        val_s = ax_s * rm16_s
        self.emu.set_gpreg(reg16_t.AX, val_s.cast_to(Type.int_16))
        self.emu.set_gpreg(reg16_t.DX, (val_s >> 16).cast_to(Type.int_16))
        self.emu.update_eflags_imul(ax_s, rm16_s)

    def div_dx_ax_rm16(self):
        rm16 = self.get_rm16()
        if rm16 == 0:
            raise Exception(self.emu.EXP_DE)
        val = (self.emu.get_gpreg(reg16_t.DX) << 16) | self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg16_t.AX, val // rm16)
        self.emu.set_gpreg(reg16_t.DX, val % rm16)

    def idiv_dx_ax_rm16(self):
        rm16_s = self.get_rm16().cast_to(Type.int_32, signed=True)
        #if rm16_s == 0:
        #    raise Exception(self.emu.EXP_DE)
        val_s = ((self.emu.get_gpreg(reg16_t.DX).cast_to(Type.int_32, signed=True) << 16)
                 | self.emu.get_gpreg(reg16_t.AX).cast_to(Type.int_32))
        self.emu.set_gpreg(reg16_t.AX, val_s // rm16_s)
        self.emu.set_gpreg(reg16_t.DX, val_s % rm16_s)

    def inc_rm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 + 1)
        self.emu.update_eflags_add(rm16, 1)

    def dec_rm16(self):
        rm16 = self.get_rm16()
        self.set_rm16(rm16 - 1)
        self.emu.update_eflags_dec(rm16)

    def call_rm16(self):
        rm16 = self.get_rm16()
        self.emu.push16(self.emu.get_ip())
        self.emu.set_ip(rm16)

    def callf_m16_16(self):
        m32 = self.get_m()
        ip = self.emu.read_mem16(m32)  # TODO: check segment, probably self.emu.get_data16(select_segment(),
        cs = self.emu.read_mem16(m32 + 2)
        self.emu.callf(cs, ip)

    def jmp_rm16(self):
        rm16 = self.get_rm16()
        self.emu.lifter_instruction.jump(None, rm16)

    def jmpf_m16_16(self):
        m32 = self.get_m()
        ip = self.emu.read_mem16(m32)
        sel = self.emu.read_mem16(m32 + 2)
        self.emu.jmpf(sel, ip)

    def push_rm16(self):
        rm16 = self.get_rm16()
        self.emu.push16(rm16)

    def enter(self):
        bytes_ = self.instr.imm16
        level = self.instr.imm8
        level &= 0x1f

        self.emu.push16(self.emu.get_gpreg(reg16_t.BP))
        ss = self.emu.get_sgreg(sgreg_t.SS)
        sp = self.emu.get_gpreg(reg16_t.SP)
        self.emu.set_gpreg(reg16_t.BP, sp)

        bp = sp - 2
        if level:
            for i in range(1, level):
                bp -= 2
                sp -= 2
                self.emu.put_data16(ss, sp, self.emu.get_data16(ss, bp))
            sp -= 2
            self.emu.put_data16(ss, sp, self.emu.get_gpreg(reg16_t.BP))
            self.emu.push16(bp)
        sp -= bytes_
        self.emu.set_gpreg(reg16_t.SP, sp)
