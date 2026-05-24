from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Sequence, cast

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .addressing_helpers import load_resolved_operand, store_resolved_operand
from .alu_helpers import (
    binary_operation,
    binary_operation_with_carry,
    compare_operation,
    masked_shift_count,
    rotate_count,
    rotate_left_operation,
    rotate_right_operation,
    rotate_through_carry_left_state,
    rotate_through_carry_right_state,
    shift_left_operation,
    shift_right_arithmetic_operation,
    shift_right_operation,
    unary_operation,
)
from .emu import EmuInstr
from .exec import ExecInstr
from .instruction import *
from .parse import ParseInstr
from .regs import coerce_reg8_t, reg8_t, reg16_t
from .stack_helpers import branch_rel8, return_far16, return_interrupt16

if TYPE_CHECKING:
    from .emulator import Emulator

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2


import logging

logger = logging.getLogger(__name__)

OpcodeHandler = Callable[..., None]

GROUP2_BYTE_SHIFT_ROTATE_HANDLERS: dict[int, str] = {
    0: "rol_rm8",
    1: "ror_rm8",
    2: "rcl_rm8",
    3: "rcr_rm8",
    4: "shl_rm8",  # SHL
    5: "shr_rm8",
    6: "shl_rm8",  # SAL aliases SHL on x86
    7: "sar_rm8",
}

class InstrBase(ExecInstr, ParseInstr, EmuInstr):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu)
        super(ExecInstr, self).__init__(emu, instr, mode32)  # ParseInstr
        super(ParseInstr, self).__init__(emu, instr, mode32)  # EmuInstr
        self.emu = emu
        self.instrfuncs: dict[int, OpcodeHandler] = {}
        self.chk: dict[int, int] = {}
        self.chsz_ad = False

        self.set_funcflag(0x00, self.add_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x02, self.add_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x04, self.add_al_imm8, CHK_IMM8)
        self.set_funcflag(0x08, self.or_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x0A, self.or_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x0C, self.or_al_imm8, CHK_IMM8)
        self.set_funcflag(0x10, self.adc_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x12, self.adc_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x20, self.and_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x22, self.and_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x24, self.and_al_imm8, CHK_IMM8)
        self.set_funcflag(0x27, self.daa, 0)
        self.set_funcflag(0x28, self.sub_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x2A, self.sub_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x2C, self.sub_al_imm8, CHK_IMM8)
        self.set_funcflag(0x2F, self.das, 0)
        self.set_funcflag(0x30, self.xor_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x32, self.xor_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x34, self.xor_al_imm8, CHK_IMM8)
        self.set_funcflag(0x37, self.aaa, 0)
        self.set_funcflag(0x38, self.cmp_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x3C, self.cmp_al_imm8, CHK_IMM8)
        self.set_funcflag(0x3F, self.aas, 0)
        self.set_funcflag(0x70, self.jo_rel8, CHK_IMM8)
        self.set_funcflag(0x71, self.jno_rel8, CHK_IMM8)
        self.set_funcflag(0x72, self.jb_rel8, CHK_IMM8)
        self.set_funcflag(0x73, self.jnb_rel8, CHK_IMM8)
        self.set_funcflag(0x74, self.jz_rel8, CHK_IMM8)
        self.set_funcflag(0x75, self.jnz_rel8, CHK_IMM8)
        self.set_funcflag(0x76, self.jbe_rel8, CHK_IMM8)
        self.set_funcflag(0x77, self.ja_rel8, CHK_IMM8)
        self.set_funcflag(0x78, self.js_rel8, CHK_IMM8)
        self.set_funcflag(0x79, self.jns_rel8, CHK_IMM8)
        self.set_funcflag(0x7A, self.jp_rel8, CHK_IMM8)
        self.set_funcflag(0x7B, self.jnp_rel8, CHK_IMM8)
        self.set_funcflag(0x7C, self.jl_rel8, CHK_IMM8)
        self.set_funcflag(0x7D, self.jnl_rel8, CHK_IMM8)
        self.set_funcflag(0x7E, self.jle_rel8, CHK_IMM8)
        self.set_funcflag(0x7F, self.jnle_rel8, CHK_IMM8)
        self.set_funcflag(0x84, self.test_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x86, self.xchg_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x88, self.mov_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x8A, self.mov_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x8E, self.mov_sreg_rm16, CHK_MODRM)
        self.set_funcflag(0x90, self.nop, 0)
        self.set_funcflag(0x9B, self.wait, 0)
        self.set_funcflag(0x9E, self.sahf, 0)
        self.set_funcflag(0x9F, self.lahf, 0)
        self.set_funcflag(0xA0, self.mov_al_moffs8, CHK_MOFFS)
        self.set_funcflag(0xA2, self.mov_moffs8_al, CHK_MOFFS)
        self.set_funcflag(0xA8, self.test_al_imm8, CHK_IMM8)
        for i in range(8):
            self.set_funcflag(0xB0 + i, self.mov_r8_imm8, CHK_IMM8)
        self.set_funcflag(0xC6, self.mov_rm8_imm8, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xCA, self.retf_imm16, CHK_IMM16)
        self.set_funcflag(0xCB, self.retf, 0)
        self.set_funcflag(0xCC, self.int3, 0)
        self.set_funcflag(0xCD, self.int_imm8, CHK_IMM8)
        self.set_funcflag(0xCF, self.iret, 0)
        self.set_funcflag(0xD0, self.code_d0_d2, CHK_MODRM)
        self.set_funcflag(0xD2, self.code_d0_d2, CHK_MODRM)
        self.set_funcflag(0xD4, self.aam, CHK_IMM8)
        self.set_funcflag(0xD5, self.aad, CHK_IMM8)
        self.set_funcflag(0xD6, self.salc, 0)
        self.set_funcflag(0xD8, self.esc, CHK_MODRM)
        self.set_funcflag(0xD9, self.esc, CHK_MODRM)
        self.set_funcflag(0xDA, self.esc, CHK_MODRM)
        self.set_funcflag(0xDB, self.esc, CHK_MODRM)
        self.set_funcflag(0xDC, self.esc, CHK_MODRM)
        self.set_funcflag(0xDD, self.esc, CHK_MODRM)
        self.set_funcflag(0xDE, self.esc, CHK_MODRM)
        self.set_funcflag(0xDF, self.esc, CHK_MODRM)
        self.set_funcflag(0xE4, self.in_al_imm8, CHK_IMM8)
        self.set_funcflag(0xE6, self.out_imm8_al, CHK_IMM8)
        self.set_funcflag(0xEB, self.jmp, CHK_IMM8)
        self.set_funcflag(0xEC, self.in_al_dx, 0)
        self.set_funcflag(0xEE, self.out_dx_al, 0)
        self.set_funcflag(0xF5, self.cmc, 0)
        self.set_funcflag(0xF8, self.clc, 0)
        self.set_funcflag(0xF9, self.stc, 0)
        self.set_funcflag(0xFA, self.cli, 0)
        self.set_funcflag(0xFB, self.sti, 0)
        self.set_funcflag(0xFC, self.cld, 0)
        self.set_funcflag(0xFD, self.std, 0)
        self.set_funcflag(0xF4, self.hlt, 0)

        self.set_funcflag(0x0F20, self.mov_r32_crn, CHK_MODRM)
        self.set_funcflag(0x0F22, self.mov_crn_r32, CHK_MODRM)
        self.set_funcflag(0x0F90, self.seto_rm8, CHK_MODRM)
        self.set_funcflag(0x0F91, self.setno_rm8, CHK_MODRM)
        self.set_funcflag(0x0F92, self.setb_rm8, CHK_MODRM)
        self.set_funcflag(0x0F93, self.setnb_rm8, CHK_MODRM)
        self.set_funcflag(0x0F94, self.setz_rm8, CHK_MODRM)
        self.set_funcflag(0x0F95, self.setnz_rm8, CHK_MODRM)
        self.set_funcflag(0x0F96, self.setbe_rm8, CHK_MODRM)
        self.set_funcflag(0x0F97, self.seta_rm8, CHK_MODRM)
        self.set_funcflag(0x0F98, self.sets_rm8, CHK_MODRM)
        self.set_funcflag(0x0F99, self.setns_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9A, self.setp_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9B, self.setnp_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9C, self.setl_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9D, self.setnl_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9E, self.setle_rm8, CHK_MODRM)
        self.set_funcflag(0x0F9F, self.setnle_rm8, CHK_MODRM)

        self.set_funcflag(0x80, self.code_80, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0x82, self.code_82, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xC0, self.code_c0, CHK_MODRM | CHK_IMM8)
        self.set_funcflag(0xF6, self.code_f6, CHK_MODRM)
        self.set_funcflag(0xFE, self.code_fe, CHK_MODRM)

    def _ite_value(self, cond, when_true, when_false):
        expr = self.emu.lifter_instruction.irsb_c.ite(
            cond.cast_to(Type.int_1).rdt,
            when_true.rdt,
            when_false.rdt,
        )
        return self.emu._vv(expr)

    def _dispatch_modrm_reg(
        self,
        handlers: Sequence[OpcodeHandler | None],
        opcode: str,
        on_missing: Callable[[int], None] | None = None,
    ) -> None:
        reg = self.instr.modrm.reg
        if 0 <= reg < len(handlers):
            handler = handlers[reg]
            if handler is not None:
                handler()
                return
        if on_missing is not None:
            on_missing(reg)
            return
        raise RuntimeError(f"not implemented: {opcode} /{reg}")

    def _register_opcode_range(self, start: int, end: int, func: OpcodeHandler, flags: int) -> None:
        for opcode in range(start, end + 1):
            self.set_funcflag(opcode, func, flags)


    def code_d0_d2(self) -> None:
        """
        Handle the x86 Group-2 byte shifts/rotates used by opcodes 0xD0 and 0xD2.

        Keeping this as an explicit dispatch table makes it easier to audit when
        a real sample trips over one of the rarely used `/digit` encodings.
        """

        reg = self.instr.modrm.reg
        handler_name = GROUP2_BYTE_SHIFT_ROTATE_HANDLERS.get(reg)
        if handler_name is None:
            raise RuntimeError(f"not implemented: 0xd0_d2 /{reg}")
        cast(OpcodeHandler, getattr(self, handler_name))()

    def set_funcflag(self, opcode: int, func: OpcodeHandler, flags: int) -> None:
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100
        assert opcode < 0x200
        self.instrfuncs[opcode] = func
        self.chk[opcode] = flags

    def add_rm8_r8(self) -> None:
        binary_operation(self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def adc_rm8_r8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.get_r8,
            self.set_rm8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def add_r8_rm8(self) -> None:
        binary_operation(self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_add, lambda lhs, rhs: lhs + rhs)

    def adc_r8_rm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_r8,
            self.get_rm8,
            self.set_r8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def adc_al_imm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def add_al_imm8(self) -> None:
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm8_r8(self) -> None:
        binary_operation(self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_r8_rm8(self) -> None:
        binary_operation(self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_or, lambda lhs, rhs: lhs | rhs)

    def or_al_imm8(self) -> None:
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def and_rm8_r8(self) -> None:
        binary_operation(self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_r8_rm8(self) -> None:
        binary_operation(self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_and, lambda lhs, rhs: lhs & rhs)

    def and_al_imm8(self) -> None:
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )

    def sub_rm8_r8(self) -> None:
        binary_operation(self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_r8_rm8(self) -> None:
        binary_operation(self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_sub, lambda lhs, rhs: lhs - rhs)

    def sub_al_imm8(self) -> None:
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )

    def sbb_rm8_r8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            self.get_r8,
            self.set_rm8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def sbb_r8_rm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_r8,
            self.get_rm8,
            self.set_r8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def sbb_al_imm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )

    def xor_rm8_r8(self) -> None:
        binary_operation(self.emu, self.get_rm8, self.get_r8, self.set_rm8, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs)

    def xor_r8_rm8(self) -> None:
        binary_operation(self.emu, self.get_r8, self.get_rm8, self.set_r8, self.emu.update_eflags_xor, lambda lhs, rhs: lhs ^ rhs)

    def xor_al_imm8(self) -> None:
        binary_operation(
            self.emu,
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            lambda value: self.emu.set_gpreg(reg8_t.AL, value),
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )

    def cmp_rm8_r8(self) -> None:
        compare_operation(self.get_rm8, self.get_r8, self.emu.update_eflags_sub)

    def cmp_r8_rm8(self) -> None:
        compare_operation(self.get_r8, self.get_rm8, self.emu.update_eflags_sub)

    def cmp_al_imm8(self) -> None:
        compare_operation(
            lambda: self.emu.get_gpreg(reg8_t.AL),
            lambda: self.instr.imm8,
            self.emu.update_eflags_sub,
        )

    def jo_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_overflow(), self.instr.imm8)

    def jno_rel8(self) -> None:
        branch_rel8(self.emu, ~self.emu.is_overflow(), self.instr.imm8)

    def jb_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_carry(), self.instr.imm8)

    def jnb_rel8(self) -> None:  # jae
        branch_rel8(self.emu, ~self.emu.is_carry(), self.instr.imm8)

    def jz_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_zero(), self.instr.imm8)

    def jnz_rel8(self) -> None:
        branch_rel8(self.emu, ~self.emu.is_zero(), self.instr.imm8)

    def jbe_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_carry() | self.emu.is_zero(), self.instr.imm8)

    def ja_rel8(self) -> None:
        branch_rel8(self.emu, ~(self.emu.is_carry() | self.emu.is_zero()), self.instr.imm8)

    def js_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_sign(), self.instr.imm8)

    def jns_rel8(self) -> None:
        branch_rel8(self.emu, ~self.emu.is_sign(), self.instr.imm8)

    def jp_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_parity(), self.instr.imm8)

    def jnp_rel8(self) -> None:
        branch_rel8(self.emu, ~self.emu.is_parity(), self.instr.imm8)

    def jl_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_sign() != self.emu.is_overflow(), self.instr.imm8)

    def jnl_rel8(self) -> None:  # jge
        branch_rel8(self.emu, ~(self.emu.is_sign() != self.emu.is_overflow()), self.instr.imm8)

    def jle_rel8(self) -> None:
        branch_rel8(self.emu, self.emu.is_zero() | (self.emu.is_sign() != self.emu.is_overflow()), self.instr.imm8)

    def jnle_rel8(self) -> None:
        branch_rel8(self.emu, ~self.emu.is_zero() & (self.emu.is_sign() == self.emu.is_overflow()), self.instr.imm8)

    def test_rm8_r8(self) -> None:
        compare_operation(self.get_rm8, self.get_r8, self.emu.update_eflags_and)

    def xchg_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        if self.instr.modrm.mod == 3:
            self.set_r8(rm8)
            self.set_rm8(r8)
            return

        operand = self._resolved_rm_operand(8)
        self.set_r8(rm8)
        store_resolved_operand(self.emu, operand, r8)

    def mov_rm8_r8(self) -> None:
        r8 = self.get_r8()
        self.set_rm8(r8)

    def mov_r8_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_r8(rm8)

    def mov_sreg_rm16(self) -> None:
        rm16 = self.get_rm16()
        self.set_sreg(rm16)

    def nop(self) -> None:
        pass

    def wait(self) -> None:
        # WAIT only stalls until TEST is asserted; architecturally it is a no-op
        # for the real-mode concrete verifier we are using here.
        self.nop()

    def lahf(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS).cast_to(Type.int_8)
        flags_low = flags & self.emu.constant(0xD5, Type.int_8)
        self.emu.set_gpreg(reg8_t.AH, flags_low | self.emu.constant(0x02, Type.int_8))

    def lohf(self) -> None:
        self.lahf()

    def sahf(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        ah = self.emu.get_gpreg(reg8_t.AH).cast_to(Type.int_16)
        preserved = flags & self.emu.constant(0xFF2A, Type.int_16)
        new_bits = ah & self.emu.constant(0x00D5, Type.int_16)
        self.emu.set_gpreg(reg16_t.FLAGS, preserved | new_bits | self.emu.constant(0x0002, Type.int_16))

    def mov_al_moffs8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.get_moffs8())

    def mov_moffs8_al(self) -> None:
        self.set_moffs8(self.emu.get_gpreg(reg8_t.AL))

    def test_al_imm8(self) -> None:
        compare_operation(lambda: self.emu.get_gpreg(reg8_t.AL), lambda: self.instr.imm8, self.emu.update_eflags_and)

    def salc(self) -> None:
        value = self._ite_value(
            self.emu.is_carry().cast_to(Type.int_1),
            self.emu.constant(0xFF, Type.int_8),
            self.emu.constant(0x00, Type.int_8),
        )
        self.emu.set_gpreg(reg8_t.AL, value)

    def esc(self) -> None:
        if self.instr.modrm.mod != 3:
            operand = self._resolved_rm_operand(8)
            load_resolved_operand(self.emu, operand)

    def mov_r8_imm8(self) -> None:
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(coerce_reg8_t(reg), self.instr.imm8)

    def mov_rm8_imm8(self) -> None:
        self.set_rm8(self.emu.lifter_instruction.constant(self.instr.imm8, Type.int_8))

    def _update_adjust_flags(self, result, *, af=None, cf=None, of=None):
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        low = result.cast_to(Type.int_8)
        if af is not None:
            flags = self.emu.set_flag(flags, 4, af)
        if cf is not None:
            flags = self.emu.set_carry(flags, cf)
        if of is not None:
            flags = self.emu.set_overflow(flags, of)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(low))
        flags = self.emu.set_zero(flags, low == self.emu.constant(0, Type.int_8))
        flags = self.emu.set_sign(flags, low[7])
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def daa(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        overflow = self._ite_value(
            cf.cast_to(Type.int_1),
            ((al >= self.emu.constant(0x1A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1),
            ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1),
        )

        result = al
        low_added = result + self.emu.constant(0x06, Type.int_8)
        result = self._ite_value(low_adjust.cast_to(Type.int_1), low_added, result)

        high_added = result + self.emu.constant(0x60, Type.int_8)
        result = self._ite_value(high_adjust.cast_to(Type.int_1), high_added, result)
        self.emu.set_gpreg(reg8_t.AL, result)
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=high_adjust.cast_to(Type.int_1),
            of=overflow,
        )

    def das(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        cf = self.emu.is_carry()
        old_sign = al[7]

        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1) | af
        high_adjust = (al > self.emu.constant(0x99, Type.int_8)).cast_to(Type.int_1) | cf

        cf_after_low = self._ite_value(
            high_adjust,
            self.emu.constant(1, Type.int_1),
            (al <= self.emu.constant(0x05, Type.int_8)).cast_to(Type.int_1),
        )
        cf_final = self._ite_value(
            low_adjust.cast_to(Type.int_1),
            cf_after_low,
            high_adjust.cast_to(Type.int_1),
        )

        result = al
        result = self._ite_value(high_adjust, result - self.emu.constant(0x60, Type.int_8), result)
        result = self._ite_value(low_adjust, result - self.emu.constant(0x06, Type.int_8), result)
        self.emu.set_gpreg(reg8_t.AL, result)
        overflow = old_sign.cast_to(Type.int_1) & (result[7].cast_to(Type.int_1) ^ self.emu.constant(1, Type.int_1))
        self._update_adjust_flags(
            result,
            af=low_adjust.cast_to(Type.int_1),
            cf=cf_final,
            of=overflow,
        )

    def aaa(self) -> None:
        ax = self.emu.get_gpreg(reg16_t.AX)
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax + self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        new_al = self._ite_value(adjust, al + self.emu.constant(6, Type.int_8), al)
        masked_al = new_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0x7F, Type.int_8))).cast_to(Type.int_1)
        sign = ((al >= self.emu.constant(0x7A, Type.int_8)) & (al <= self.emu.constant(0xF9, Type.int_8))).cast_to(Type.int_1)
        zero = (new_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, zero)
        flags = self.emu.set_parity(flags, self.emu.chk_parity(new_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aas(self) -> None:
        ax = self.emu.get_gpreg(reg16_t.AX)
        al = self.emu.get_gpreg(reg8_t.AL)
        af = self.emu.get_flag(4)
        low_adjust = ((al & self.emu.constant(0x0F, Type.int_8)) > self.emu.constant(9, Type.int_8)).cast_to(Type.int_1)
        adjust = low_adjust | af

        result_ax = self._ite_value(adjust, ax - self.emu.constant(0x0106, Type.int_16), ax)
        self.emu.set_gpreg(reg16_t.AX, result_ax)
        pre_mask_al = result_ax.cast_to(Type.int_8)
        masked_al = pre_mask_al & self.emu.constant(0x0F, Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, masked_al)

        overflow = self._ite_value(
            low_adjust,
            self.emu.constant(0, Type.int_1),
            self._ite_value(
                af,
                ((al >= self.emu.constant(0x80, Type.int_8)) & (al <= self.emu.constant(0x85, Type.int_8))).cast_to(Type.int_1),
                self.emu.constant(0, Type.int_1),
            ),
        )
        sign = self._ite_value(
            low_adjust,
            (al > self.emu.constant(0x85, Type.int_8)).cast_to(Type.int_1),
            self._ite_value(
                af,
                ((al < self.emu.constant(0x06, Type.int_8)) | (al > self.emu.constant(0x85, Type.int_8))).cast_to(Type.int_1),
                (al >= self.emu.constant(0x80, Type.int_8)).cast_to(Type.int_1),
            ),
        )
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_flag(flags, 4, adjust)
        flags = self.emu.set_carry(flags, adjust)
        flags = self.emu.set_overflow(flags, overflow)
        flags = self.emu.set_sign(flags, sign)
        flags = self.emu.set_zero(flags, (pre_mask_al == self.emu.constant(0, Type.int_8)).cast_to(Type.int_1))
        flags = self.emu.set_parity(flags, self.emu.chk_parity(pre_mask_al))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def aam(self) -> None:
        base = self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8)
        al = self.emu.get_gpreg(reg8_t.AL)
        ah = al // base
        new_al = al % base
        self.emu.set_gpreg(reg8_t.AH, ah)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def aad(self) -> None:
        base = self.emu.constant(self.instr.imm8 & 0xFF, Type.int_8)
        ah = self.emu.get_gpreg(reg8_t.AH)
        al = self.emu.get_gpreg(reg8_t.AL)
        ax = ah.cast_to(Type.int_16) * base.cast_to(Type.int_16) + al.cast_to(Type.int_16)
        new_al = ax.cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AL, new_al)
        self.emu.set_gpreg(reg8_t.AH, self.emu.constant(0, Type.int_8))
        self._update_adjust_flags(
            new_al,
            af=self.emu.constant(0, Type.int_1),
            cf=self.emu.constant(0, Type.int_1),
            of=self.emu.constant(0, Type.int_1),
        )

    def retf_imm16(self) -> None:
        return_far16(self.emu, self.instr.imm16)

    def retf(self) -> None:
        return_far16(self.emu)


    def int3(self) -> None:
        self.instr.imm8 = 3
        self.int_imm8()

    def int_imm8(self) -> None:
        next_ip = self.emu.get_ip() + self.emu.constant(self.instr.size, Type.int_16)
        self.emu.lifter_instruction.put(next_ip.cast_to(Type.int_32), "ip_at_syscall")
        # Model real-mode interrupts as synthetic call targets so CFG/decompilation
        # can treat them like normal helper functions.
        self.emu.set_gpreg(reg16_t.IP, self.emu.constant(self.instr.imm8, Type.int_16))
        self.emu.lifter_instruction.jump(None, 0xFF000 + self.instr.imm8, JumpKind.Call)

    def iret(self) -> None:
        return_interrupt16(self.emu)

    def in_al_imm8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(self.instr.imm8))

    def out_imm8_al(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(self.instr.imm8, al)

    def jmp(self) -> None:
        branch_rel8(self.emu, True, self.instr.imm8)

    def in_al_dx(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(dx))

    def out_dx_al(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(dx, al)

    def cmc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags ^ self.emu.constant(0x0001, Type.int_16))

    def clc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags & self.emu.constant(0xFFFE, Type.int_16))

    def stc(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        self.emu.set_gpreg(reg16_t.FLAGS, flags | self.emu.constant(0x0001, Type.int_16))

    def cli(self) -> None:
        self.emu.set_interrupt(False)

    def sti(self) -> None:
        self.emu.set_interrupt(True)

    def cld(self) -> None:
        self.emu.set_direction(False)

    def std(self) -> None:
        self.emu.set_direction(True)

    def hlt(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        self.emu.do_halt(True)

    def ltr_rm16(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        rm16 = self.get_rm16()
        self.emu.set_tr(rm16)

    def mov_r32_crn(self) -> None:
        crn = self.get_crn()
        self.emu.set_gpreg(self.instr.modrm.rm, crn)

    def mov_crn_r32(self) -> None:
        if not self.emu.chk_ring(0):
            raise Exception(self.emu.EXP_GP)
        r32 = self.emu.get_gpreg(self.instr.modrm.rm)
        self.set_crn(r32)

    def seto_rm8(self) -> None:
        self.set_rm8(self.emu.is_overflow())

    def setno_rm8(self) -> None:
        self.set_rm8(not self.emu.is_overflow())

    def setb_rm8(self) -> None:
        self.set_rm8(self.emu.is_carry())

    def setnb_rm8(self) -> None:
        self.set_rm8(not self.emu.is_carry())

    def setz_rm8(self) -> None:
        self.set_rm8(self.emu.is_zero())

    def setnz_rm8(self) -> None:
        self.set_rm8(not self.emu.is_zero())

    def setbe_rm8(self) -> None:
        self.set_rm8(self.emu.is_carry() or self.emu.is_zero())

    def seta_rm8(self) -> None:
        self.set_rm8(not (self.emu.is_carry() or self.emu.is_zero()))

    def sets_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign())

    def setns_rm8(self) -> None:
        self.set_rm8(not self.emu.is_sign())

    def setp_rm8(self) -> None:
        self.set_rm8(self.emu.is_parity())

    def setnp_rm8(self) -> None:
        self.set_rm8(not self.emu.is_parity())

    def setl_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign() != self.emu.is_overflow())

    def setnl_rm8(self) -> None:
        self.set_rm8(self.emu.is_sign() == self.emu.is_overflow())

    def setle_rm8(self) -> None:
        self.set_rm8(self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow()))

    def setnle_rm8(self) -> None:
        self.set_rm8(not self.emu.is_zero() and (self.emu.is_sign() == self.emu.is_overflow()))

    def code_80(self) -> None:
        self._dispatch_modrm_reg(
            (
                self.add_rm8_imm8,
                self.or_rm8_imm8,
                self.adc_rm8_imm8,
                self.sbb_rm8_imm8,
                self.and_rm8_imm8,
                self.sub_rm8_imm8,
                self.xor_rm8_imm8,
                self.cmp_rm8_imm8,
            ),
            "0x80",
        )

    def code_82(self) -> None:
        self.code_80()

    def code_c0(self) -> None:
        self._dispatch_modrm_reg(
            (
                self.rol_rm8_imm8,
                self.ror_rm8_imm8,
                self.rcl_rm8_imm8,
                self.rcr_rm8_imm8,
                self.shl_rm8_imm8,
                self.shr_rm8_imm8,
                self.sal_rm8_imm8,
                self.sar_rm8_imm8,
            ),
            "0xc0",
        )

    def code_f6(self) -> None:
        self._dispatch_modrm_reg(
            (
                self.test_rm8_imm8,
                self.test_rm8_imm8,
                self.not_rm8,
                self.neg_rm8,
                self.mul_ax_al_rm8,
                self.imul_ax_al_rm8,
                self.div_al_ah_rm8,
                self.idiv_al_ah_rm8,
            ),
            "0xf6",
        )

    def code_fe(self) -> None:
        self._dispatch_modrm_reg((self.inc_rm8, self.dec_rm8), "0xfe")

    def _group2_rm8_count(self):
        """
        Resolve the implicit shift/rotate count for opcodes 0xD0 and 0xD2.

        0xD0 uses a fixed count of 1, while 0xD2 uses CL.
        """

        if self.instr.opcode == 0xD2:
            return self.emu.get_gpreg(reg8_t.CL)
        return self.emu.constant(1, Type.int_8)

    def _masked_shift_count8(self, count):
        return masked_shift_count(self.emu, count, 8)

    def _rotate_count8(self, count, modulo):
        return rotate_count(self.emu, count, modulo, 8)

    def shl_rm8(self) -> None:
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self._group2_rm8_count(),
            8,
        )

    def rol_rm8(self) -> None:
        rotate_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_rol,
            self._group2_rm8_count(),
            8,
        )

    def ror_rm8(self) -> None:
        rotate_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_ror,
            self._group2_rm8_count(),
            8,
        )

    def rcl_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcl_rm8(rm8, count)

    def rcr_rm8(self) -> None:
        rm8 = self.get_rm8()
        count = self._group2_rm8_count()
        self._rcr_rm8(rm8, count)

    def shr_rm8(self) -> None:
        shift_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shr,
            self._group2_rm8_count(),
            8,
        )

    def sar_rm8(self) -> None:
        shift_right_arithmetic_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_sar,
            self._group2_rm8_count(),
            8,
        )

    def inc_rm8(self) -> None:
        unary_operation(self.get_rm8, self.set_rm8, self.emu.update_eflags_inc, lambda value: value + 1)

    def dec_rm8(self) -> None:
        unary_operation(self.get_rm8, self.set_rm8, self.emu.update_eflags_dec, lambda value: value - 1)

    def add_rm8_imm8(self) -> None:
        binary_operation(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_add,
            lambda lhs, rhs: lhs + rhs,
        )

    def or_rm8_imm8(self) -> None:
        binary_operation(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_or,
            lambda lhs, rhs: lhs | rhs,
        )

    def adc_rm8_imm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_adc,
            lambda lhs, rhs, carry: lhs + rhs + carry,
            8,
        )

    def sbb_rm8_imm8(self) -> None:
        binary_operation_with_carry(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_sbb,
            lambda lhs, rhs, carry: lhs - rhs - carry,
            8,
        )


    def and_rm8_imm8(self) -> None:
        binary_operation(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_and,
            lambda lhs, rhs: lhs & rhs,
        )


    def sub_rm8_imm8(self) -> None:
        binary_operation(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_sub,
            lambda lhs, rhs: lhs - rhs,
        )


    def xor_rm8_imm8(self) -> None:
        binary_operation(
            self.emu,
            self.get_rm8,
            lambda: self.instr.imm8,
            self.set_rm8,
            self.emu.update_eflags_xor,
            lambda lhs, rhs: lhs ^ rhs,
        )


    def cmp_rm8_imm8(self) -> None:
        compare_operation(
            self.get_rm8,
            lambda: self.instr.imm8,
            self.emu.update_eflags_sub,
        )


    def shl_rm8_imm8(self) -> None:
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self.instr.imm8,
            8,
        )

    def rol_rm8_imm8(self) -> None:
        rotate_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_rol,
            self.instr.imm8,
            8,
        )

    def ror_rm8_imm8(self) -> None:
        rotate_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_ror,
            self.instr.imm8,
            8,
        )

    def rcl_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcl_rm8(rm8, count)

    def rcr_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        count = self.emu.constant(self.instr.imm8, Type.int_8)
        self._rcr_rm8(rm8, count)


    def shr_rm8_imm8(self) -> None:
        shift_right_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shr,
            self.instr.imm8,
            8,
        )


    def sal_rm8_imm8(self) -> None:
        shift_left_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_shl,
            self.instr.imm8,
            8,
        )


    def sar_rm8_imm8(self) -> None:
        shift_right_arithmetic_operation(
            self.emu,
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_sar,
            self.instr.imm8,
            8,
        )

    def _rcl_rm8(self, value, count) -> None:
        result, cf, overflow = rotate_through_carry_left_state(self.emu, value, count, 8, self._ite_value)
        if cf is None:
            self.set_rm8(value)
            return
        self.set_rm8(result)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf)
        flags = self.emu.set_overflow(flags, self._ite_value(count == self.emu.constant(1, Type.int_8), overflow, self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)

    def _rcr_rm8(self, value, count) -> None:
        result, cf, overflow = rotate_through_carry_right_state(self.emu, value, count, 8, self._ite_value)
        if cf is None:
            self.set_rm8(value)
            return
        self.set_rm8(result)
        flags = self.emu.get_gpreg(reg16_t.FLAGS)
        flags = self.emu.set_carry(flags, cf)
        flags = self.emu.set_overflow(flags, self._ite_value(count == self.emu.constant(1, Type.int_8), overflow, self.emu.get_flag(11)))
        self.emu.set_gpreg(reg16_t.FLAGS, flags)


    def test_rm8_imm8(self) -> None:
        compare_operation(self.get_rm8, lambda: self.instr.imm8, self.emu.update_eflags_and)


    def not_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(~rm8)


    def neg_rm8(self) -> None:
        unary_operation(
            self.get_rm8,
            self.set_rm8,
            self.emu.update_eflags_sub,
            lambda value: self.emu.constant(0, Type.int_8) - value,
        )


    def mul_ax_al_rm8(self) -> None:
        rm8 = self.get_rm8()
        al = self.emu.get_gpreg(reg8_t.AL)
        val = al.cast_to(Type.int_16) * rm8.cast_to(Type.int_16)
        self.emu.set_gpreg(reg16_t.AX, val)
        self.emu.update_eflags_mul(al, rm8)


    def imul_ax_al_rm8(self) -> None:
        rm8_s = self.get_rm8().signed
        al_s = self.emu.get_gpreg(reg8_t.AL).signed
        val_s = al_s * rm8_s
        self.emu.set_gpreg(reg16_t.AX, val_s)
        self.emu.update_eflags_imul(al_s, rm8_s)


    def div_al_ah_rm8(self) -> None:
        rm8 = self.get_rm8().cast_to(Type.int_16)
        ax = self.emu.get_gpreg(reg16_t.AX)
        self.emu.set_gpreg(reg8_t.AL, ax // rm8)
        self.emu.set_gpreg(reg8_t.AH, ax % rm8)


    def idiv_al_ah_rm8(self) -> None:
        rm8_s = self.get_rm8().cast_to(Type.int_16, signed=True)
        ax_s = self.emu.get_gpreg(reg16_t.AX).signed
        self.emu.set_gpreg(reg8_t.AL, ax_s // rm8_s)
        self.emu.set_gpreg(reg8_t.AH, ax_s % rm8_s)

    def set_chsz_ad(self, ad):
        self.chsz_ad = ad
