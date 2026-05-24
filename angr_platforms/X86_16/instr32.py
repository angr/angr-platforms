import struct

from pyvex.lifting.util import Type

from .addressing_helpers import advance_eip32, load_far_pointer
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    unary_operation,
)
from .debug import ERROR, INFO
from .exception import EXCEPTION, EXP_DE
from .instr_base import InstrBase
from .instruction import *
from .jcc_condition import _consume_last_condition_branch_8616
from .regs import coerce_reg32_t, reg8_t, reg16_t, reg32_t
from .stack_helpers import (
    branch_rel32,
    emit_far_call32,
    emit_far_jump32,
    emit_near_call32,
    emit_near_jump32,
    far_return_ip32,
    leave32,
    pop32_register,
    pop_all32,
    pop_flags32,
    pop_segment32,
    push32_register,
    push_all32,
    push_flags32,
    push_immediate32,
    push_segment32,
    return_near32,
)
from .string_helpers import (
    repeat_jump,
    repeat_prefix_cond,
    string_advance_indices,
    string_compare_values,
    string_load,
    string_source_segment,
)


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
        binary_operation(self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)


    def adc_rm32_r32(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            self.get_r32,
            self.set_rm32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def add_r32_rm32(self):
        binary_operation(self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def adc_r32_rm32(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_r32,
            self.get_rm32,
            self.set_r32,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def add_eax_imm32(self):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, lambda value: self.emu.set_gpreg(reg32_t.EAX, value), self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def push_es(self):
        push_segment32(self.emu, reg16_t.ES)

    def pop_es(self):
        pop_segment32(self.emu, reg16_t.ES)

    def or_rm32_r32(self):
        binary_operation(self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_r32_rm32(self):
        binary_operation(self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_eax_imm32(self):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, lambda value: self.emu.set_gpreg(reg32_t.EAX, value), self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def push_ss(self):
        push_segment32(self.emu, reg16_t.SS)

    def pop_ss(self):
        pop_segment32(self.emu, reg16_t.SS)

    def push_ds(self):
        push_segment32(self.emu, reg16_t.DS)

    def pop_ds(self):
        pop_segment32(self.emu, reg16_t.DS)

    def and_rm32_r32(self):
        binary_operation(self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_r32_rm32(self):
        binary_operation(self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_eax_imm32(self):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, lambda value: self.emu.set_gpreg(reg32_t.EAX, value), self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def sub_rm32_r32(self):
        binary_operation(self.emu, self.get_rm32, self.get_r32, self.set_rm32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_r32_rm32(self):
        binary_operation(self.emu, self.get_r32, self.get_rm32, self.set_r32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_eax_imm32(self):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, lambda value: self.emu.set_gpreg(reg32_t.EAX, value), self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def xor_rm32_r32(self):
        binary_operation(self.emu, self.get_rm32, self.get_r32, self.set_rm32, lambda lhs, rhs: None, lambda lhs, rhs: lhs ^ rhs)

    def xor_r32_rm32(self):
        binary_operation(self.emu, self.get_r32, self.get_rm32, self.set_r32, lambda lhs, rhs: None, lambda lhs, rhs: lhs ^ rhs)

    def xor_eax_imm32(self):
        binary_operation(self.emu, lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, lambda value: self.emu.set_gpreg(reg32_t.EAX, value), lambda lhs, rhs: None, lambda lhs, rhs: lhs ^ rhs)

    def cmp_rm32_r32(self):
        compare_operation(self.get_rm32, self.get_r32, self.emu.update_eflags_sub)

    def cmp_r32_rm32(self):
        compare_operation(self.get_r32, self.get_rm32, self.emu.update_eflags_sub)

    def cmp_eax_imm32(self):
        compare_operation(lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, self.emu.update_eflags_sub)

    def inc_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_add,
            lambda value: value + 1,
        )

    def dec_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        unary_operation(
            lambda: self.emu.get_gpreg(reg),
            lambda value: self.emu.set_gpreg(reg, value),
            self.emu.update_eflags_sub,
            lambda value: value - 1,
        )

    def push_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        push32_register(self.emu, reg)

    def pop_r32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        pop32_register(self.emu, reg)

    def pushad(self):
        push_all32(self.emu)

    def popad(self):
        pop_all32(self.emu)

    def push_imm32(self):
        push_immediate32(self.emu, self.instr.imm32)

    def imul_r32_rm32_imm32(self):
        rm32_s = self.get_rm32()
        self.set_r32(rm32_s * self.instr.imm32)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm32)

    def push_imm8(self):
        push_immediate32(self.emu, self.instr.imm8)

    def imul_r32_rm32_imm8(self):
        rm32_s = self.get_rm32()
        self.set_r32(rm32_s * self.instr.imm8)
        self.emu.update_eflags_imul(rm32_s, self.instr.imm8)

    def test_rm32_r32(self):
        compare_operation(self.get_rm32, self.get_r32, self.emu.update_eflags_and)

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
        emit_far_call32(self.emu, self.instr.ptr16, self.instr.imm32, far_return_ip32(self.emu, self.instr.size))

    def pushf(self):
        push_flags32(self.emu)

    def popf(self):
        pop_flags32(self.emu)

    def mov_eax_moffs32(self):
        self.emu.set_gpreg(reg32_t.EAX, self.get_moffs32())

    def mov_moffs32_eax(self):
        self.set_moffs32(self.emu.get_gpreg(reg32_t.EAX))

    def cmps_m8_m8(self):
        repeat_cond = repeat_prefix_cond(self.emu, self.instr)

        si = self.emu.get_gpreg(reg32_t.ESI)
        di = self.emu.get_gpreg(reg32_t.EDI)
        m8_s = string_load(self.emu, string_source_segment(self.instr), si, 1)
        m8_d = string_load(self.emu, reg16_t.ES, di, 1)
        string_compare_values(m8_s, m8_d, self.emu.update_eflags_sub)
        string_advance_indices(self.emu, 1, reg32_t.ESI, reg32_t.EDI)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond, zf_sensitive=True)

    def cmps_m32_m32(self):
        repeat_cond = repeat_prefix_cond(self.emu, self.instr)

        si = self.emu.get_gpreg(reg32_t.ESI)
        di = self.emu.get_gpreg(reg32_t.EDI)
        m32_s = string_load(self.emu, string_source_segment(self.instr), si, 4)
        m32_d = string_load(self.emu, reg16_t.ES, di, 4)
        string_compare_values(m32_s, m32_d, self.emu.update_eflags_sub)
        string_advance_indices(self.emu, 4, reg32_t.ESI, reg32_t.EDI)

        if repeat_cond is not None:
            repeat_jump(self.emu, self.instr, repeat_cond, zf_sensitive=True)

    def test_eax_imm32(self):
        compare_operation(lambda: self.emu.get_gpreg(reg32_t.EAX), lambda: self.instr.imm32, self.emu.update_eflags_and)

    def mov_r32_imm32(self):
        reg = self.instr.opcode & ((1 << 3) - 1)
        self.emu.set_gpreg(coerce_reg32_t(reg), self.instr.imm32)

    def ret(self):
        return_near32(self.emu)

    def mov_rm32_imm32(self):
        self.set_rm32(self.instr.imm32)

    def leave(self):
        leave32(self.emu)

    def in_eax_imm8(self):
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(self.instr.imm8))

    def out_imm8_eax(self):
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(self.instr.imm8, eax)

    def call_rel32(self):
        target = near_relative_target32(self.emu, self.instr.imm32)
        emit_near_call32(self.emu, target)

    def jmp_rel32(self):
        target = near_relative_target32(self.emu, self.instr.imm32)
        emit_near_jump32(self.emu, target)

    def jmpf_ptr16_32(self):
        emit_far_jump32(self.emu, self.instr.ptr16, self.instr.imm32)

    def in_eax_dx(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg32_t.EAX, self.emu.in_io32(dx))

    def out_dx_eax(self):
        dx = self.emu.get_gpreg(reg16_t.DX)
        eax = self.emu.get_gpreg(reg32_t.EAX)
        self.emu.out_io32(dx, eax)

    def jo_rel32(self):
        branch_rel32(self.emu, self.emu.is_overflow(), self.instr.imm32)

    def jno_rel32(self):
        branch_rel32(self.emu, ~self.emu.is_overflow(), self.instr.imm32)

    def jb_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jb", self.emu.is_carry()), self.instr.imm32)

    def jnb_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jnb", ~self.emu.is_carry()), self.instr.imm32)

    def jz_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jz", self.emu.is_zero()), self.instr.imm32)

    def jnz_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jnz", ~self.emu.is_zero()), self.instr.imm32)

    def jbe_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jbe", self.emu.is_carry() or self.emu.is_zero()), self.instr.imm32)

    def ja_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("ja", not (self.emu.is_carry() or self.emu.is_zero())), self.instr.imm32)

    def js_rel32(self):
        branch_rel32(self.emu, self.emu.is_sign(), self.instr.imm32)

    def jns_rel32(self):
        branch_rel32(self.emu, ~self.emu.is_sign(), self.instr.imm32)

    def jp_rel32(self):
        branch_rel32(self.emu, self.emu.is_parity(), self.instr.imm32)

    def jnp_rel32(self):
        branch_rel32(self.emu, ~self.emu.is_parity(), self.instr.imm32)

    def jl_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jl", self.emu.is_sign() != self.emu.is_overflow()), self.instr.imm32)

    def jnl_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jge", self.emu.is_sign() == self.emu.is_overflow()), self.instr.imm32)

    def jle_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jle", self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow())), self.instr.imm32)

    def jnle_rel32(self):
        branch_rel32(self.emu, self._branch_cond_8616("jg", not self.emu.is_zero() and (self.emu.is_sign() == self.emu.is_overflow())), self.instr.imm32)

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
        self._dispatch_modrm_reg(
            (
                self.add_rm32_imm32,
                self.or_rm32_imm32,
                self.adc_rm32_imm32,
                self.sbb_rm32_imm32,
                self.and_rm32_imm32,
                self.sub_rm32_imm32,
                self.xor_rm32_imm32,
                self.cmp_rm32_imm32,
            ),
            "0x81",
            lambda reg: ERROR("not implemented: 0x81 /%d\n", reg),
        )

    def code_83(self):
        self._dispatch_modrm_reg(
            (
                self.add_rm32_imm8,
                self.or_rm32_imm8,
                self.adc_rm32_imm8,
                self.sbb_rm32_imm8,
                self.and_rm32_imm8,
                self.sub_rm32_imm8,
                self.xor_rm32_imm8,
                self.cmp_rm32_imm8,
            ),
            "0x83",
            lambda reg: ERROR("not implemented: 0x83 /%d\n", reg),
        )

    def code_c1(self):
        self._dispatch_modrm_reg(
            (
                None,
                None,
                None,
                None,
                self.shl_rm32_imm8,
                self.shr_rm32_imm8,
                self.sal_rm32_imm8,
                self.sar_rm32_imm8,
            ),
            "0xc1",
            lambda reg: ERROR("not implemented: 0xc1 /%d\n", reg),
        )

    def code_d3(self):
        self._dispatch_modrm_reg(
            (
                None,
                None,
                None,
                None,
                self.shl_rm32_cl,
                self.shr_rm32_cl,
                self.sal_rm32_cl,
                self.sar_rm32_cl,
            ),
            "0xd3",
            lambda reg: ERROR("not implemented: 0xd3 /%d\n", reg),
        )

    def code_f7(self):
        self._dispatch_modrm_reg(
            (
                self.test_rm32_imm32,
                None,
                self.not_rm32,
                self.neg_rm32,
                self.mul_edx_eax_rm32,
                self.imul_edx_eax_rm32,
                self.div_edx_eax_rm32,
                self.idiv_edx_eax_rm32,
            ),
            "0xf7",
            lambda reg: ERROR("not implemented: 0xf7 /%d\n", reg),
        )

    def code_ff(self):
        self._dispatch_modrm_reg(
            (
                self.inc_rm32,
                self.dec_rm32,
                self.call_rm32,
                self.callf_m16_32,
                self.jmp_rm32,
                self.jmpf_m16_32,
                self.push_rm32,
                None,
            ),
            "0xff",
            lambda reg: ERROR("not implemented: 0xff /%d\n", reg),
        )

    def code_0f00(self):
        self._dispatch_modrm_reg(
            (None, None, None, self.ltr_rm16),
            "0x0f00",
            lambda reg: ERROR("not implemented: 0x0f00 /%d\n", reg),
        )

    def code_0f01(self):
        self._dispatch_modrm_reg(
            (None, None, self.lgdt_m32, self.lidt_m32),
            "0x0f01",
            lambda reg: ERROR("not implemented: 0x0f01 /%d\n", reg),
        )

    def add_rm32_imm32(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm32, self.set_rm32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def or_rm32_imm32(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm32, self.set_rm32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def adc_rm32_imm32(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_add,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def sbb_rm32_imm32(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm32,
            self.set_rm32,
            self.emu.update_eflags_sub,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def and_rm32_imm32(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm32, self.set_rm32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def sub_rm32_imm32(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm32, self.set_rm32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def xor_rm32_imm32(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm32, self.set_rm32, lambda lhs, rhs: None, lambda lhs, rhs: lhs ^ rhs)

    def cmp_rm32_imm32(self):
        compare_operation(self.get_rm32, lambda: self.instr.imm32, self.emu.update_eflags_sub)

    def add_rm32_imm8(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm8, self.set_rm32, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def or_rm32_imm8(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm8, self.set_rm32, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def adc_rm32_imm8(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_add,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            32,
        )

    def sbb_rm32_imm8(self):
        binary_operation_with_carry(
            self.emu,
            self.get_rm32,
            lambda: self.instr.imm8,
            self.set_rm32,
            self.emu.update_eflags_sub,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            32,
        )

    def and_rm32_imm8(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm8, self.set_rm32, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def sub_rm32_imm8(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm8, self.set_rm32, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def xor_rm32_imm8(self):
        binary_operation(self.emu, self.get_rm32, lambda: self.instr.imm8, self.set_rm32, lambda lhs, rhs: None, lambda lhs, rhs: lhs ^ rhs)

    def cmp_rm32_imm8(self):
        compare_operation(self.get_rm32, lambda: self.instr.imm8, self.emu.update_eflags_sub)

    def shl_rm32_imm8(self):
        rm32 = self.get_rm32()
        count = masked_shift_count(self.emu, self.instr.imm8, 32)
        self.set_rm32(rm32 << count)
        self.emu.update_eflags_shl(rm32, count)

    def shr_rm32_imm8(self):
        rm32 = self.get_rm32()
        count = masked_shift_count(self.emu, self.instr.imm8, 32)
        self.set_rm32(rm32 >> count)
        self.emu.update_eflags_shr(rm32, count)

    def sal_rm32_imm8(self):
        rm32_s = self.get_rm32()
        count = masked_shift_count(self.emu, self.instr.imm8, 32)
        self.set_rm32(rm32_s << count)

    def sar_rm32_imm8(self):
        rm32_s = self.get_rm32()
        count = masked_shift_count(self.emu, self.instr.imm8, 32)
        self.set_rm32(rm32_s >> count)

    def shl_rm32_cl(self):
        rm32 = self.get_rm32()
        cl = masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)
        self.set_rm32(rm32 << cl)
        self.emu.update_eflags_shl(rm32, cl)

    def shr_rm32_cl(self):
        rm32 = self.get_rm32()
        cl = masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)
        self.set_rm32(rm32 >> cl)
        self.emu.update_eflags_shr(rm32, cl)

    def sal_rm32_cl(self):
        rm32_s = self.get_rm32()
        cl = masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)
        self.set_rm32(rm32_s << cl)

    def sar_rm32_cl(self):
        rm32_s = self.get_rm32()
        cl = masked_shift_count(self.emu, self.emu.get_gpreg(reg8_t.CL), 32)
        self.set_rm32(rm32_s >> cl)

    def test_rm32_imm32(self):
        imm32 = struct.unpack("<I", self.emu.get_code8(0, 4))[0]
        self.emu.set_gpreg(reg32_t.EIP, advance_eip32(self.emu, 4))
        compare_operation(self.get_rm32, lambda: imm32, self.emu.update_eflags_and)

    def not_rm32(self):
        unary_operation(self.get_rm32, self.set_rm32, None, lambda value: ~value)

    def neg_rm32(self):
        unary_operation(self.get_rm32, self.set_rm32, self.emu.update_eflags_neg, lambda value: (value.signed * -1).cast_to(Type.int_32))

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
        unary_operation(self.get_rm32, self.set_rm32, self.emu.update_eflags_add, lambda value: value + 1)

    def dec_rm32(self):
        unary_operation(self.get_rm32, self.set_rm32, self.emu.update_eflags_sub, lambda value: value - 1)

    def call_rm32(self):
        rm32 = self.get_rm32()
        emit_near_call32(self.emu, rm32)

    def callf_m16_32(self):
        seg, offset = self._resolved_rm_address()
        eip, cs = load_far_pointer(
            self.emu,
            seg,
            offset,
            32,
            address_bits=self.effective_address_bits(),
        )
        INFO(2, "cs = 0x%04x, eip = 0x%08x", cs, eip)
        emit_far_call32(self.emu, cs, eip, far_return_ip32(self.emu, self.instr.size))

    def jmp_rm32(self):
        rm32 = self.get_rm32()
        emit_near_jump32(self.emu, rm32)

    def jmpf_m16_32(self):
        seg, offset = self._resolved_rm_address()
        eip, sel = load_far_pointer(
            self.emu,
            seg,
            offset,
            32,
            address_bits=self.effective_address_bits(),
        )
        emit_far_jump32(self.emu, sel, eip)

    def push_rm32(self):
        rm32 = self.get_rm32()
        push_immediate32(self.emu, rm32)
    def _branch_cond_8616(self, kind: str, fallback):
        direct = _consume_last_condition_branch_8616(self.emu.lifter_instruction, self.emu, kind)
        return fallback if direct is None else direct
