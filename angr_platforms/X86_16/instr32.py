import struct

from pyvex.lifting.util import Type

from .debug import ERROR, INFO
from .exception import EXCEPTION, EXP_DE
from .instr_base import InstrBase
from .instruction import *
from .regs import reg8_t, reg16_t, reg32_t


class Instr32(InstrBase):

    def __init__(self, emu, instr):
        super().__init__(emu, instr, mode32=True)  # X86Instruction

        self.set_funcflag(0x01, self.add_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x03, self.add_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x05, self.add_eax_imm32, CHK_IMM32)
        self.set_funcflag(0x06, self.push_es, 0)
        self.set_funcflag(0x07, self.pop_es, 0)
        self.set_funcflag(0x09, self.or_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x0B, self.or_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x0D, self.or_eax_imm32, CHK_IMM32)
        self.set_funcflag(0x11, self.adc_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x13, self.adc_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x16, self.push_ss, 0)
        self.set_funcflag(0x17, self.pop_ss, 0)
        self.set_funcflag(0x1E, self.push_ds, 0)
        self.set_funcflag(0x1F, self.pop_ds, 0)
        self.set_funcflag(0x21, self.and_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x23, self.and_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x25, self.and_eax_imm32, CHK_IMM32)
        self.set_funcflag(0x29, self.sub_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x2B, self.sub_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x2D, self.sub_eax_imm32, CHK_IMM32)
        self.set_funcflag(0x31, self.xor_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x33, self.xor_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x35, self.xor_eax_imm32, CHK_IMM32)
        self.set_funcflag(0x39, self.cmp_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x3B, self.cmp_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x3D, self.cmp_eax_imm32, CHK_IMM32)

        for i in range(8):
            self.set_funcflag(0x40 + i, self.inc_r32, 0)
            self.set_funcflag(0x48 + i, self.dec_r32, 0)
            self.set_funcflag(0x50 + i, self.push_r32, 0)
            self.set_funcflag(0x58 + i, self.pop_r32, 0)

        self.set_funcflag(0x60, self.pushad, 0)
        self.set_funcflag(0x61, self.popad, 0)
        self.set_funcflag(0x68, self.push_imm32, CHK_IMM32)
        self.set_funcflag(0x69, self.imul_r32_rm32_imm32, CHK_MODRM | CHK_IMM32)
        self.set_funcflag(0x6A, self.push_imm8, CHK_IMM8)
        self.set_funcflag(0x6B, self.imul_r32_rm32_imm8, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0x85, self.test_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x87, self.xchg_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x89, self.mov_rm32_r32, CHK_MODRM)
        self.set_funcflag(0x8B, self.mov_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x8C, self.mov_rm32_sreg, CHK_MODRM)
        self.set_funcflag(0x8D, self.lea_r32_m32, CHK_MODRM)

        for i in range(1, 8):
            self.set_funcflag(0x90 + i, self.xchg_r32_eax, CHK_IMM32)

        self.set_funcflag(0x98, self.cwde, 0)
        self.set_funcflag(0x99, self.cdq, 0)
        self.set_funcflag(0x9A, self.callf_ptr16_32, CHK_PTR16 | CHK_IMM32)
        self.set_funcflag(0x9C, self.pushf, 0)
        self.set_funcflag(0x9D, self.popf, 0)
        self.set_funcflag(0xA1, self.mov_eax_moffs32, CHK_MOFFS)
        self.set_funcflag(0xA3, self.mov_moffs32_eax, CHK_MOFFS)
        self.set_funcflag(0xA6, self.cmps_m8_m8, 0)
        self.set_funcflag(0xA7, self.cmps_m32_m32, 0)
        self.set_funcflag(0xA9, self.test_eax_imm32, CHK_IMM32)

        for i in range(8):
            self.set_funcflag(0xB8 + i, self.mov_r32_imm32, CHK_IMM32)

        self.set_funcflag(0xC3, self.ret, 0)
        self.set_funcflag(0xC7, self.mov_rm32_imm32, CHK_MODRM | CHK_IMM32)
        self.set_funcflag(0xC9, self.leave, 0)
        self.set_funcflag(0xE5, self.in_eax_imm8, CHK_IMM8)
        self.set_funcflag(0xE7, self.out_imm8_eax, CHK_IMM8)
        self.set_funcflag(0xE8, self.call_rel32, CHK_IMM32)
        self.set_funcflag(0xE9, self.jmp_rel32, CHK_IMM32)
        self.set_funcflag(0xEA, self.jmpf_ptr16_32, CHK_PTR16 | CHK_IMM32)
        self.set_funcflag(0xED, self.in_eax_dx, 0)
        self.set_funcflag(0xEF, self.out_dx_eax, 0)

        self.set_funcflag(0x0F80, self.jo_rel32, CHK_IMM32)
        self.set_funcflag(0x0F81, self.jno_rel32, CHK_IMM32)
        self.set_funcflag(0x0F82, self.jb_rel32, CHK_IMM32)
        self.set_funcflag(0x0F83, self.jnb_rel32, CHK_IMM32)
        self.set_funcflag(0x0F84, self.jz_rel32, CHK_IMM32)
        self.set_funcflag(0x0F85, self.jnz_rel32, CHK_IMM32)
        self.set_funcflag(0x0F86, self.jbe_rel32, CHK_IMM32)
        self.set_funcflag(0x0F87, self.ja_rel32, CHK_IMM32)
        self.set_funcflag(0x0F88, self.js_rel32, CHK_IMM32)
        self.set_funcflag(0x0F89, self.jns_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8A, self.jp_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8B, self.jnp_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8C, self.jl_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8D, self.jnl_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8E, self.jle_rel32, CHK_IMM32)
        self.set_funcflag(0x0F8F, self.jnle_rel32, CHK_IMM32)

        self.set_funcflag(0x0FAF, self.imul_r32_rm32, CHK_MODRM)
        self.set_funcflag(0x0FB6, self.movzx_r32_rm8, CHK_MODRM)
        self.set_funcflag(0x0FB7, self.movzx_r32_rm16, CHK_MODRM)
        self.set_funcflag(0x0FBE, self.movsx_r32_rm8, CHK_MODRM)
        self.set_funcflag(0x0FBF, self.movsx_r32_rm16, CHK_MODRM)

        self.set_funcflag(0x81, self.code_81, CHK_MODRM | CHK_IMM32)
        self.set_funcflag(0x83, self.code_83, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xC1, self.code_c1, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xD3, self.code_d3, CHK_MODRM)
        self.set_funcflag(0xF7, self.code_f7, CHK_MODRM)
        self.set_funcflag(0xFF, self.code_ff, CHK_MODRM)
        self.set_funcflag(0x0F00, self.code_0f00, CHK_MODRM)
        self.set_funcflag(0x0F01, self.code_0f01, CHK_MODRM)

    def add_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.set_rm32(rm32 + r32)
        self.emu.update_eflags_add(rm32, r32)


    def adc_rm32_r32(self) -> None:
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        carry = self.emu.is_carry().cast_to(Type.int_32)
        self.set_rm8(rm32 + r32 + carry)
        self.emu.update_eflags_adc(rm32, r32, carry)

    def add_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(r32 + rm32)
        self.emu.update_eflags_add(r32, rm32)

    def adc_r32_rm32(self) -> None:
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        carry = self.emu.is_carry().cast_to(Type.int_32)
        self.set_r32(r32 + rm32 + carry)
        self.emu.update_eflags_adc(r32, rm32, carry)

    def add_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, eax + self.instr.imm32)
        self.emu.update_eflags_add(eax, self.instr.imm32)

    def push_es(self):
        self.emu.push32(self.emu.get_segment(reg16_t.ES))

    def pop_es(self):
        self.emu.set_segment(reg16_t.ES, self.emu.pop32())

    def or_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.set_rm32(rm32 | r32)
        self.emu.update_eflags_or(rm32, r32)

    def or_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(r32 | rm32)
        self.emu.update_eflags_or(r32, rm32)

    def or_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, eax | self.instr.imm32)
        self.emu.update_eflags_or(eax, self.instr.imm32)

    def push_ss(self):
        self.emu.push32(self.emu.get_segment(reg16_t.SS))

    def pop_ss(self):
        self.emu.set_segment(reg16_t.SS, self.emu.pop32())

    def push_ds(self):
        self.emu.push32(self.emu.get_segment(reg16_t.DS))

    def pop_ds(self):
        self.emu.set_segment(reg16_t.DS, self.emu.pop32())

    def and_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.set_rm32(rm32 & r32)
        self.emu.update_eflags_and(rm32, r32)

    def and_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(r32 & rm32)
        self.emu.update_eflags_and(r32, rm32)

    def and_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, eax & self.instr.imm32)
        self.emu.update_eflags_and(eax, self.instr.imm32)

    def sub_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.set_rm32(rm32 - r32)
        self.emu.update_eflags_sub(rm32, r32)

    def sub_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(r32 - rm32)
        self.emu.update_eflags_sub(r32, rm32)

    def sub_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, eax - self.instr.imm32)
        self.emu.update_eflags_sub(eax, self.instr.imm32)

    def xor_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.set_rm32(rm32 ^ r32)

    def xor_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(r32 ^ rm32)

    def xor_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, eax ^ self.instr.imm32)

    def cmp_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.emu.update_eflags_sub(rm32, r32)

    def cmp_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.emu.update_eflags_sub(r32, rm32)

    def cmp_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.update_eflags_sub(eax, self.instr.imm32)

    def inc_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        r32 = self.emu.get_gpreg(reg)
        self.emu.set_gpreg(reg, r32 + 1)
        self.emu.update_eflags_add(r32, 1)

    def dec_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        r32 = self.emu.get_gpreg(reg)
        self.emu.set_gpreg(reg, r32 - 1)
        self.emu.update_eflags_sub(r32, 1)

    def push_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        self.emu.push32(self.emu.get_gpreg(reg))

    def pop_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        self.emu.set_gpreg(reg, self.emu.pop32())

    def pushad(self):
        esp = self.emu.get_gpreg(reg32_t.ESP)
        self.emu.push32(self.emu.get_gpreg(reg32_t.EAX))
        self.emu.push32(self.emu.get_gpreg(reg32_t.ECX))
        self.emu.push32(self.emu.get_gpreg(reg32_t.EDX))
        self.emu.push32(self.emu.get_gpreg(reg32_t.EBX))
        self.emu.push32(esp)
        self.emu.push32(self.emu.get_gpreg(reg32_t.EBP))
        self.emu.push32(self.emu.get_gpreg(reg32_t.ESI))
        self.emu.push32(self.emu.get_gpreg(reg32_t.EDI))

    def popad(self):
        self.emu.set_gpreg(reg32_t.EDI, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.ESI, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.EBP, self.emu.pop32())
        esp = self.emu.pop32()
        self.emu.set_gpreg(reg32_t.EBX, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.EDX, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.ECX, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.EAX, self.emu.pop32())
        self.emu.set_gpreg(reg32_t.ESP, esp)

    def push_imm32(self):
        self.emu.push32(self.instr.imm32)

    def imul_r32_rm32_imm32(self):
        rm32_s = self.get_rm32()
        self.set_r32(rm32_s * self.instr.imm32)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm32)

    def push_imm8(self):
        self.emu.push32(self.instr.imm8)

    def imul_r32_rm32_imm8(self):
        rm32_s = self.get_rm32()
        self.set_r32(rm32_s * self.instr.imm8)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm8)

    def test_rm32_r32(self):
        rm32 = self.get_rm32()
        r32 = self.get_r32()
        self.emu.update_eflags_and(rm32, r32)

    def xchg_r32_rm32(self):
        r32 = self.get_r32()
        rm32 = self.get_rm32()
        self.set_r32(rm32)
        self.set_rm32(r32)

    def mov_rm32_r32(self):
        r32 = self.get_r32()
        self.set_rm32(r32)

    def mov_r32_rm32(self):
        rm32 = self.get_rm32()
        self.set_r32(rm32)

    def mov_rm32_sreg(self):
        sreg = self.get_sreg()
        self.set_rm32(sreg)

    def lea_r32_m32(self):
        m32 = self.get_m()
        self.set_r32(m32)

    def xchg_r32_eax(self):
        r32 = self.get_r32()
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.set_r32(eax)
        self.emu.set_gpreg(reg32_t.EAX, r32)

    def cwde(self):
        ax_s = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg32_t.EAX, ax_s)

    def cdq(self):
        eax = self.emu.get_gpreg(reg32_t.EAX).signed
        self.emu.set_gpreg(reg32_t.EDX, eax.sar(self.emu.constant(31, Type.int_8)))

    def callf_ptr16_32(self):
        self.emu.callf(self.instr.ptr16, self.instr.imm32)

    def pushf(self):
        self.emu.push32(self.emu.get_eflags())

    def popf(self):
        self.emu.set_eflags(self.emu.pop32())

    def mov_eax_moffs32(self):
        self.emu.set_gpreg(reg32_t.EAX, self.get_moffs32())

    def mov_moffs32_eax(self):
        self.set_moffs32(self.emu.get_gpreg(reg32_t.EAX))

    def cmps_m8_m8(self):
        while True:
            m8_s = self.emu.get_data8(
                self.select_segment(), self.emu.get_gpreg(reg32_t.ESI),
            )
            m8_d = self.emu.get_data8(reg16_t.ES, self.emu.get_gpreg(reg32_t.EDI))
            self.emu.update_eflags_sub(m8_s, m8_d)

            self.emu.update_gpreg(reg32_t.ESI, -1 if self.emu.is_direction() else 1)
            self.emu.update_gpreg(reg32_t.EDI, -1 if self.emu.is_direction() else 1)

            if self.instr.pre_repeat:
                self.emu.update_gpreg(reg32_t.ECX, -1)
                if self.instr.pre_repeat == REPZ:
                    if not self.emu.get_gpreg(reg32_t.ECX) or not self.emu.is_zero():
                        break
                elif self.instr.pre_repeat == REPNZ:
                    if not self.emu.get_gpreg(reg32_t.ECX) or self.emu.is_zero():
                        break
            else:
                break

    def cmps_m32_m32(self):
        while True:
            m32_s = self.emu.get_data32(
                self.select_segment(), self.emu.get_gpreg(reg32_t.ESI),
            )
            m32_d = self.emu.get_data32(reg16_t.ES, self.emu.get_gpreg(reg32_t.EDI))
            self.emu.update_eflags_sub(m32_s, m32_d)

            self.emu.update_gpreg(reg32_t.ESI, -1 if self.emu.is_direction() else 1)
            self.emu.update_gpreg(reg32_t.EDI, -1 if self.emu.is_direction() else 1)

            if self.instr.pre_repeat:
                self.emu.update_gpreg(reg32_t.ECX, -1)
                if self.instr.pre_repeat == REPZ:
                    if not self.emu.get_gpreg(reg32_t.ECX) or not self.emu.is_zero():
                        break
                elif self.instr.pre_repeat == REPNZ:
                    if not self.emu.get_gpreg(reg32_t.ECX) or self.emu.is_zero():
                        break
            else:
                break

    def test_eax_imm32(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.update_eflags_and(eax, self.instr.imm32)

    def mov_r32_imm32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        self.emu.set_gpreg(reg32_t(reg), self.instr.imm32)

    def ret(self):
        self.emu.set_eip(self.emu.pop32())

    def mov_rm32_imm32(self):
        self.set_rm32(self.instr.imm32)

    def leave(self):
        ebp = self.emu.get_gpreg(reg32_t.EBP)
        self.emu.set_gpreg(reg32_t.ESP, ebp)
        self.emu.set_gpreg(reg32_t.EBP, self.emu.pop32())

    def in_eax_imm8(self):
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(self.instr.imm8))

    def out_imm8_eax(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(self.instr.imm8, eax)

    def call_rel32(self):
        self.emu.push32(self.emu.get_eip())
        self.emu.update_eip(self.instr.imm32)

    def jmp_rel32(self):
        self.emu.update_eip(self.instr.imm32)

    def jmpf_ptr16_32(self):
        self.emu.jmpf(self.instr.ptr16, self.instr.imm32)

    def in_eax_dx(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(dx))

    def out_dx_eax(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(dx, eax)

    def jo_rel32(self):
        if self.emu.is_overflow():
            self.emu.update_eip(self.instr.imm32)

    def jno_rel32(self):
        ip = self.emu.get_gpreg(reg16_t.IP).cast_to(Type.int_32) + self.emu.constant(self.instr.imm32, Type.int_32).signed + 6
        self.emu.lifter_instruction.jump(self.emu.is_overflow(), ip)

    def jb_rel32(self):
        if self.emu.is_carry():
            self.emu.update_eip(self.instr.imm32)

    def jnb_rel32(self):
        if not self.emu.is_carry():
            self.emu.update_eip(self.instr.imm32)

    def jz_rel32(self):
        if self.emu.is_zero():
            self.emu.update_eip(self.instr.imm32)

    def jnz_rel32(self):
        if not self.emu.is_zero():
            self.emu.update_eip(self.instr.imm32)

    def jbe_rel32(self):
        if self.emu.is_carry() or self.emu.is_zero():
            self.emu.update_eip(self.instr.imm32)

    def ja_rel32(self):
        if not (self.emu.is_carry() or self.emu.is_zero()):
            self.emu.update_eip(self.instr.imm32)

    def js_rel32(self):
        if self.emu.is_sign():
            self.emu.update_eip(self.instr.imm32)

    def jns_rel32(self):
        if not self.emu.is_sign():
            self.emu.update_eip(self.instr.imm32)

    def jp_rel32(self):
        if self.emu.is_parity():
            self.emu.update_eip(self.instr.imm32)

    def jnp_rel32(self):
        if not self.emu.is_parity():
            self.emu.update_eip(self.instr.imm32)

    def jl_rel32(self):
        if self.emu.is_sign() != self.emu.is_overflow():
            self.emu.update_eip(self.instr.imm32)

    def jnl_rel32(self):
        if self.emu.is_sign() == self.emu.is_overflow():
            self.emu.update_eip(self.instr.imm32)

    def jle_rel32(self):
        if self.emu.is_zero() or (
            self.emu.is_sign() != self.emu.is_overflow()
        ):
            self.emu.update_eip(self.instr.imm32)

    def jnle_rel32(self):
        if not self.emu.is_zero() and (
            self.emu.is_sign() == self.emu.is_overflow()
        ):
            self.emu.update_eip(self.instr.imm32)

    def imul_r32_rm32(self):
        r32_s = self.get_r32()
        rm32_s = self.get_rm32()
        self.set_r32(r32_s * rm32_s)
        self.emu.update_eflags_imul(r32_s, rm32_s)

    def movzx_r32_rm8(self):
        rm8 = self.get_rm8()
        self.set_r32(rm8)

    def movzx_r32_rm16(self):
        rm16 = self.get_rm16()
        self.set_r32(rm16)

    def movsx_r32_rm8(self):
        rm8_s = self.get_rm8()
        self.set_r32(rm8_s)

    def movsx_r32_rm16(self):
        rm16_s = self.get_rm16()
        self.set_r32(rm16_s)

    def code_81(self):
        match self.instr.modrm.reg:
            case 0:
                self.add_rm32_imm32()
            case 1:
                self.or_rm32_imm32()
            case 2:
                self.adc_rm32_imm32()
            case 3:
                self.sbb_rm32_imm32()
            case 4:
                self.and_rm32_imm32()
            case 5:
                self.sub_rm32_imm32()
            case 6:
                self.xor_rm32_imm32()
            case 7:
                self.cmp_rm32_imm32()
            case _:
                ERROR("not implemented: 0x81 /%d\n", self.instr.modrm.reg)

    def code_83(self):
        match self.instr.modrm.reg:
            case 0:
                self.add_rm32_imm8()
            case 1:
                self.or_rm32_imm8()
            case 2:
                self.adc_rm32_imm8()
            case 3:
                self.sbb_rm32_imm8()
            case 4:
                self.and_rm32_imm8()
            case 5:
                self.sub_rm32_imm8()
            case 6:
                self.xor_rm32_imm8()
            case 7:
                self.cmp_rm32_imm8()
            case _:
                ERROR("not implemented: 0x83 /%d\n", self.instr.modrm.reg)

    def code_c1(self):
        match self.instr.modrm.reg:
            case 4:
                self.shl_rm32_imm8()
            case 5:
                self.shr_rm32_imm8()
            case 6:
                self.sal_rm32_imm8()
            case 7:
                self.sar_rm32_imm8()
            case _:
                ERROR("not implemented: 0xc1 /%d\n", self.instr.modrm.reg)

    def code_d3(self):
        match self.instr.modrm.reg:
            case 4:
                self.shl_rm32_cl()
            case 5:
                self.shr_rm32_cl()
            case 6:
                self.sal_rm32_cl()
            case 7:
                self.sar_rm32_cl()
            case _:
                ERROR("not implemented: 0xd3 /%d\n", self.instr.modrm.reg)

    def code_f7(self):
        match self.instr.modrm.reg:
            case 0:
                self.test_rm32_imm32()
            case 2:
                self.not_rm32()
            case 3:
                self.neg_rm32()
            case 4:
                self.mul_edx_eax_rm32()
            case 5:
                self.imul_edx_eax_rm32()
            case 6:
                self.div_edx_eax_rm32()
            case 7:
                self.idiv_edx_eax_rm32()
            case _:
                ERROR("not implemented: 0xf7 /%d\n", self.instr.modrm.reg)

    def code_ff(self):
        match self.instr.modrm.reg:
            case 0:
                self.inc_rm32()
            case 1:
                self.dec_rm32()
            case 2:
                self.call_rm32()
            case 3:
                self.callf_m16_32()
            case 4:
                self.jmp_rm32()
            case 5:
                self.jmpf_m16_32()
            case 6:
                self.push_rm32()
            case _:
                ERROR("not implemented: 0xff /%d\n", self.instr.modrm.reg)

    def code_0f00(self):
        match self.instr.modrm.reg:
            case 3:
                self.ltr_rm16()
            case _:
                ERROR("not implemented: 0x0f00 /%d\n", self.instr.modrm.reg)

    def code_0f01(self):
        match self.instr.modrm.reg:
            case 2:
                self.lgdt_m32()
            case 3:
                self.lidt_m32()
            case _:
                ERROR("not implemented: 0x0f01 /%d\n", self.instr.modrm.reg)

    def add_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 + self.instr.imm32)
        self.emu.update_eflags_add(rm32, self.instr.imm32)

    def or_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 | self.instr.imm32)
        self.emu.update_eflags_or(rm32, self.instr.imm32)

    def adc_rm32_imm32(self):
        rm32 = self.get_rm32()
        cf = self.emu.is_carry()
        self.set_rm32(rm32 + self.instr.imm32 + cf)
        self.emu.update_eflags_add(rm32, self.instr.imm32 + cf)

    def sbb_rm32_imm32(self):
        rm32 = self.get_rm32()
        cf = self.emu.is_carry()
        self.set_rm32(rm32 - self.instr.imm32 - cf)
        self.emu.update_eflags_sub(rm32, self.instr.imm32 + cf)

    def and_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 & self.instr.imm32)
        self.emu.update_eflags_and(rm32, self.instr.imm32)

    def sub_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 - self.instr.imm32)
        self.emu.update_eflags_sub(rm32, self.instr.imm32)

    def xor_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 ^ self.instr.imm32)

    def cmp_rm32_imm32(self):
        rm32 = self.get_rm32()
        self.emu.update_eflags_sub(rm32, self.instr.imm32)

    def add_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 + self.instr.imm8)
        self.emu.update_eflags_add(rm32, self.instr.imm8)

    def or_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 | self.instr.imm8)
        self.emu.update_eflags_or(rm32, self.instr.imm8)

    def adc_rm32_imm8(self):
        rm32 = self.get_rm32()
        cf = self.emu.is_carry()
        self.set_rm32(rm32 + self.instr.imm8 + cf)
        self.emu.update_eflags_add(rm32, self.instr.imm8 + cf)

    def sbb_rm32_imm8(self):
        rm32 = self.get_rm32()
        cf = self.emu.is_carry()
        self.set_rm32(rm32 - self.instr.imm8 - cf)
        self.emu.update_eflags_sub(rm32, self.instr.imm8 + cf)

    def and_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 & self.instr.imm8)
        self.emu.update_eflags_and(rm32, self.instr.imm8)

    def sub_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 - self.instr.imm8)
        self.emu.update_eflags_sub(rm32, self.instr.imm8)

    def xor_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 ^ self.instr.imm8)

    def cmp_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.emu.update_eflags_sub(rm32, self.instr.imm8)

    def shl_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 << self.instr.imm8)
        self.emu.update_eflags_shl(rm32, self.instr.imm8)

    def shr_rm32_imm8(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 >> self.instr.imm8)
        self.emu.update_eflags_shr(rm32, self.instr.imm8)

    def sal_rm32_imm8(self):
        rm32_s = self.get_rm32()
        self.set_rm32(rm32_s << self.instr.imm8)

    def sar_rm32_imm8(self):
        rm32_s = self.get_rm32()
        self.set_rm32(rm32_s >> self.instr.imm8)

    def shl_rm32_cl(self):
        rm32 = self.get_rm32()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm32(rm32 << cl)
        self.emu.update_eflags_shl(rm32, cl)

    def shr_rm32_cl(self):
        rm32 = self.get_rm32()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm32(rm32 >> cl)
        self.emu.update_eflags_shr(rm32, cl)

    def sal_rm32_cl(self):
        rm32_s = self.get_rm32()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm32(rm32_s << cl)

    def sar_rm32_cl(self):
        rm32_s = self.get_rm32()
        cl = self.emu.get_gpreg(reg8_t.CL)
        self.set_rm32(rm32_s >> cl)

    def test_rm32_imm32(self):
        rm32 = self.get_rm32()
        imm32 = struct.unpack("<I", self.emu.get_code8(0, 4))[0]
        self.emu.update_eip(4)
        self.emu.update_eflags_and(rm32, imm32)

    def not_rm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(~rm32)

    def neg_rm32(self):
        rm32_s = self.get_rm32()
        self.set_rm32(-rm32_s)
        self.emu.update_eflags_sub(0, rm32_s)

    def mul_edx_eax_rm32(self):
        rm32 = self.get_rm32()
        eax = self.emu.get_gpreg(reg32_t.EAX)
        val = eax * rm32
        self.emu.set_gpreg(reg32_t.EAX, val & 0xFFFFFFFF)
        self.emu.set_gpreg(reg32_t.EDX, (val >> 32) & 0xFFFFFFFF)
        self.emu.update_eflags_mul(eax, rm32)

    def imul_edx_eax_rm32(self):
        rm32_s = self.get_rm32()
        eax_s = self.emu.get_gpreg(reg32_t.EAX)
        val_s = eax_s * rm32_s
        self.emu.set_gpreg(reg32_t.EAX, val_s & 0xFFFFFFFF)
        self.emu.set_gpreg(reg32_t.EDX, (val_s >> 32) & 0xFFFFFFFF)
        self.emu.update_eflags_imul(eax_s, rm32_s)

    def div_edx_eax_rm32(self):
        rm32 = self.get_rm32()
        EXCEPTION(EXP_DE, not rm32)
        val = (self.emu.get_gpreg(reg32_t.EDX) << 32) | self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, val // rm32)
        self.emu.set_gpreg(reg32_t.EDX, val % rm32)

    def idiv_edx_eax_rm32(self):
        rm32_s = self.get_rm32()
        EXCEPTION(EXP_DE, not rm32_s)
        val_s = (self.emu.get_gpreg(reg32_t.EDX) << 32) | self.emu.get_gpreg(reg32_t.EAX)
        self.emu.set_gpreg(reg32_t.EAX, val_s // rm32_s)
        self.emu.set_gpreg(reg32_t.EDX, val_s % rm32_s)

    def inc_rm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 + 1)
        self.emu.update_eflags_add(rm32, 1)

    def dec_rm32(self):
        rm32 = self.get_rm32()
        self.set_rm32(rm32 - 1)
        self.emu.update_eflags_sub(rm32, 1)

    def call_rm32(self):
        rm32 = self.get_rm32()
        self.emu.push32(self.emu.get_eip())
        self.emu.set_eip(rm32)

    def callf_m16_32(self):
        m48 = self.get_m()
        eip = self.emu.read_mem32(m48)
        cs = self.emu.read_mem16(m48 + 4)
        INFO(2, "cs = 0x%04x, eip = 0x%08x", cs, eip)
        self.emu.callf(cs, eip)

    def jmp_rm32(self):
        rm32 = self.get_rm32()
        self.emu.set_eip(rm32)

    def jmpf_m16_32(self):
        m48 = self.get_m()
        eip = self.emu.read_mem32(m48)
        sel = self.emu.read_mem16(m48 + 4)
        self.emu.jmpf(sel, eip)

    def push_rm32(self):
        rm32 = self.get_rm32()
        self.emu.push32(rm32)
