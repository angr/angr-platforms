from typing import TYPE_CHECKING, Any, Callable, Dict

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .emu import EmuInstr
from .exec import ExecInstr
from .instruction import *
from .parse import ParseInstr
from .regs import reg8_t, reg16_t, sgreg_t

if TYPE_CHECKING:
    from .emulator import Emulator

CHSZ_NONE: int = 0
CHSZ_OP: int = 1
CHSZ_AD: int = 2


class InstrBase(ExecInstr, ParseInstr, EmuInstr):
    def __init__(self, emu: Emulator, instr: InstrData, mode32: bool):
        super().__init__(emu)
        super(ExecInstr, self).__init__(emu, instr, mode32)  # ParseInstr
        super(ParseInstr, self).__init__(emu, instr, mode32)  # EmuInstr
        self.emu = emu
        self.instrfuncs: Dict[int, Callable[[Dict[str, Any]], None]] = {}
        self.chk: Dict[int, int] = {}
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
        self.set_funcflag(0x28, self.sub_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x2A, self.sub_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x2C, self.sub_al_imm8, CHK_IMM8)
        self.set_funcflag(0x30, self.xor_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x32, self.xor_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x34, self.xor_al_imm8, CHK_IMM8)
        self.set_funcflag(0x38, self.cmp_rm8_r8, CHK_MODRM)
        self.set_funcflag(0x3A, self.cmp_r8_rm8, CHK_MODRM)
        self.set_funcflag(0x3C, self.cmp_al_imm8, CHK_IMM8)
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
        self.set_funcflag(0x9F, self.lohf, 0)
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
        self.set_funcflag(0xE4, self.in_al_imm8, CHK_IMM8)
        self.set_funcflag(0xE6, self.out_imm8_al, CHK_IMM8)
        self.set_funcflag(0xEB, self.jmp, CHK_IMM8)
        self.set_funcflag(0xEC, self.in_al_dx, 0)
        self.set_funcflag(0xEE, self.out_dx_al, 0)
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


    def code_d0_d2(self):
        reg = self.instr.modrm.reg
        if reg == 0:
            self.rol_rm8()
        elif reg == 1:
            self.ror_rm8()
        elif reg == 2:
            self.rcl_rm8()
        elif reg == 3:
            self.rcr_rm8()
        elif reg == 4:
            self.shl_rm8()  # sal
        elif reg == 5:
            self.shr_rm8()
        elif reg == 6:
            self.shl_rm8()  # sal
        elif reg == 5:
            self.sar_rm8()
        else:
            raise RuntimeError(f"not implemented: 0xd0_d2 /{reg}")

    def set_funcflag(self, opcode: int, func: Callable[[Dict[str, Any]], None], flags: int):
        if opcode >> 8 == 0x0F:
            opcode = (opcode & 0xFF) | 0x0100
        assert opcode < 0x200
        self.instrfuncs[opcode] = func
        self.chk[opcode] = flags

    def add_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 + r8)
        self.emu.update_eflags_add(rm8, r8)

    def adc_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_rm8(rm8 + r8 + carry)
        self.emu.update_eflags_adc(rm8, r8, carry)

    def add_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 + rm8)
        self.emu.update_eflags_add(r8, rm8)

    def adc_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        carry = self.emu.is_carry().cast_to(Type.int_8)
        self.set_r8(r8 + rm8 + carry)
        self.emu.update_eflags_adc(r8, rm8, carry)

    def add_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al + self.instr.imm8)
        self.emu.update_eflags_add(al, self.instr.imm8)

    def or_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 | r8)
        self.emu.update_eflags_or(rm8, r8)

    def or_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 | rm8)
        self.emu.update_eflags_or(r8, rm8)

    def or_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al | self.instr.imm8)
        self.emu.update_eflags_or(al, self.instr.imm8)

    def and_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 & r8)
        self.emu.update_eflags_and(rm8, r8)

    def and_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 & rm8)
        self.emu.update_eflags_and(r8, rm8)

    def and_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al & self.instr.imm8)
        self.emu.update_eflags_and(al, self.instr.imm8)

    def sub_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 - r8)
        self.emu.update_eflags_sub(rm8, r8)

    def sub_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 - rm8)
        self.emu.update_eflags_sub(r8, rm8)

    def sub_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al - self.instr.imm8)
        self.emu.update_eflags_sub(al, self.instr.imm8)

    def xor_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.set_rm8(rm8 ^ r8)
        self.emu.update_eflags_xor(rm8, r8)

    def xor_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(r8 ^ rm8)
        self.emu.update_eflags_xor(rm8, r8)

    def xor_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.set_gpreg(reg8_t.AL, al ^ self.instr.imm8)
        self.emu.update_eflags_xor(al, self.instr.imm8)

    def cmp_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.emu.update_eflags_sub(rm8, r8)

    def cmp_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.emu.update_eflags_sub(r8, rm8)

    def cmp_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.update_eflags_sub(al, self.instr.imm8)

    def jo_rel8(self) -> None:
        result = self.emu.is_overflow()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jno_rel8(self) -> None:
        result = self.emu.is_overflow()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jb_rel8(self) -> None:
        result = self.emu.is_carry()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jnb_rel8(self) -> None:  # jae
        result = self.emu.is_carry()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jz_rel8(self) -> None:
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not self.emu.is_zero(), ip)

    def jnz_rel8(self) -> None:
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(self.emu.is_zero(), ip)

    def jbe_rel8(self) -> None:
        result = self.emu.is_carry() or self.emu.is_zero()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def ja_rel8(self) -> None:
        result = self.emu.is_carry() or self.emu.is_zero()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def js_rel8(self) -> None:
        result = self.emu.is_sign()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jns_rel8(self) -> None:
        result = self.emu.is_sign()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jp_rel8(self) -> None:
        result = self.emu.is_parity()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jnp_rel8(self) -> None:
        result = self.emu.is_parity()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jl_rel8(self) -> None:
        result = self.emu.is_sign() != self.emu.is_overflow()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jnl_rel8(self) -> None:  # jge
        result = self.emu.is_sign() != self.emu.is_overflow()
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def jle_rel8(self) -> None:
        result = self.emu.is_zero() or (self.emu.is_sign() != self.emu.is_overflow())
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(not result, ip, JumpKind.Boring)

    def jnle_rel8(self) -> None:
        result = ~self.emu.is_zero() and (self.emu.is_sign() == self.emu.is_overflow())
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(result, ip, JumpKind.Boring)

    def test_rm8_r8(self) -> None:
        rm8 = self.get_rm8()
        r8 = self.get_r8()
        self.emu.update_eflags_and(rm8, r8)

    def xchg_r8_rm8(self) -> None:
        r8 = self.get_r8()
        rm8 = self.get_rm8()
        self.set_r8(rm8)
        self.set_rm8(r8)

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

    def lohf(self) -> None:
        flags = self.emu.get_gpreg(reg16_t.FLAGS).cast_to(Type.int_8)
        self.emu.set_gpreg(reg8_t.AH, flags)

    def mov_al_moffs8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.get_moffs8())

    def mov_moffs8_al(self) -> None:
        self.set_moffs8(self.emu.get_gpreg(reg8_t.AL))

    def test_al_imm8(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.update_eflags_and(al, self.instr.imm8)

    def mov_r8_imm8(self) -> None:
        reg = self.instr.opcode & 0b111
        self.emu.set_gpreg(reg8_t(reg), self.instr.imm8)

    def mov_rm8_imm8(self) -> None:
        self.set_rm8(self.emu.lifter_instruction.constant(self.instr.imm8, Type.int_8))

    def retf_imm16(self) -> None:
        self.set_gpreg(reg16_t.SP, self.get_gpreg(reg16_t.SP) + self.instr.imm16)
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        self.emu.lifter_instruction.jump(None, self.emu.trans_v2p(0, cs, ip), jumpkind=JumpKind.Ret)

    def retf(self) -> None:
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        self.emu.set_sgreg(sgreg_t.CS, cs)
        self.emu.lifter_instruction.jump(None, self.emu.trans_v2p(0, cs, ip), jumpkind=JumpKind.Ret)

    def int3(self) -> None:
        self.instr.imm8 = 3
        self.int_imm8()

    def int_imm8(self) -> None:
        self.emu.lifter_instruction.put(self.emu.constant(self.instr.imm8), "ip_at_syscall")
        exit = self.emu.constant(self.instr.imm8) == 0x21 and self.emu.get_gpreg(reg8_t.AH) == 0x4c
        self.emu.lifter_instruction.jump(~exit, 0, JumpKind.Exit)
        self.emu.lifter_instruction.jump(None, self.emu.get_gpreg(reg16_t.IP) + 2, JumpKind.Syscall)
        #raise Exception("INT %x" % self.instr.imm8)
        #self.emu.queue_interrupt(self.instr.imm8, False)

    def iret(self) -> None:
        ip = self.emu.pop16()
        cs = self.emu.pop16()
        flags = self.emu.pop16()
        self.emu.set_gpreg(reg16_t.FLAGS, flags)
        self.emu.set_sgreg(sgreg_t.CS, cs)
        self.emu.lifter_instruction.jump(None, self.emu.trans_v2p(0, cs, ip), jumpkind=JumpKind.Ret)

    def in_al_imm8(self) -> None:
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(self.instr.imm8))

    def out_imm8_al(self) -> None:
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(self.instr.imm8, al)

    def jmp(self) -> None:
        ip = self.emu.get_gpreg(reg16_t.IP) + self.emu.constant(self.instr.imm8 + 2, Type.int_8).widen_signed(Type.int_16)
        self.emu.lifter_instruction.jump(None, ip, JumpKind.Boring)

    def in_al_dx(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        self.emu.set_gpreg(reg8_t.AL, self.emu.in_io8(dx))

    def out_dx_al(self) -> None:
        dx = self.emu.get_gpreg(reg16_t.DX)
        al = self.emu.get_gpreg(reg8_t.AL)
        self.emu.out_io8(dx, al)

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
        self.set_rm8(
            self.instr, not self.emu.is_zero() and (self.emu.is_sign() == self.emu.is_overflow()),
        )

    def code_80(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.add_rm8_imm8()
        elif reg == 1:
            self.or_rm8_imm8()
        elif reg == 2:
            self.adc_rm8_imm8()
        elif reg == 3:
            self.sbb_rm8_imm8()
        elif reg == 4:
            self.and_rm8_imm8()
        elif reg == 5:
            self.sub_rm8_imm8()
        elif reg == 6:
            self.xor_rm8_imm8()
        elif reg == 7:
            self.cmp_rm8_imm8()
        else:
            raise RuntimeError(f"not implemented: 0x80 /{reg}")

    def code_82(self) -> None:
        self.code_80()

    def code_c0(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 4:
            self.shl_rm8_imm8()
        elif reg == 5:
            self.shr_rm8_imm8()
        elif reg == 6:
            self.sal_rm8_imm8()
        elif reg == 7:
            self.sar_rm8_imm8()
        else:
            raise RuntimeError(f"not implemented: 0xc0 /{reg}")

    def code_f6(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.test_rm8_imm8()
        elif reg == 2:
            self.not_rm8()
        elif reg == 3:
            self.neg_rm8()
        elif reg == 4:
            self.mul_ax_al_rm8()
        elif reg == 5:
            self.imul_ax_al_rm8()
        elif reg == 6:
            self.div_al_ah_rm8()
        elif reg == 7:
            self.idiv_al_ah_rm8()
        else:
            raise RuntimeError(f"not implemented: 0xf6 /{reg}")

    def code_fe(self) -> None:
        reg = self.instr.modrm.reg
        if reg == 0:
            self.inc_rm8()
        elif reg == 1:
            self.dec_rm8()
        else:
            raise RuntimeError(f"not implemented: 0xf6 /{reg}")

    def inc_rm8(self) -> None:
        rm8 = self.get_rm8() + 1
        self.set_rm8(rm8)
        self.emu.update_eflags_inc(rm8)

    def dec_rm8(self) -> None:
        rm8 = self.get_rm8() - 1
        self.set_rm8(rm8)
        self.emu.update_eflags_dec(rm8)

    def add_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 + self.instr.imm8)
        self.emu.update_eflags_add(rm8, self.instr.imm8)

    def or_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 | self.instr.imm8)
        self.emu.update_eflags_or(rm8, self.instr.imm8)

    def adc_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        cf = self.emu.is_carry()
        self.set_rm8(rm8 + self.instr.imm8 + cf)
        self.emu.update_eflags_add(rm8, self.instr.imm8 + cf)

    def sbb_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        cf = self.emu.is_carry()
        self.set_rm8(rm8 - self.instr.imm8 - cf)
        self.emu.update_eflags_sub(rm8, self.instr.imm8 + cf)


    def and_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 & self.instr.imm8)
        self.emu.update_eflags_and(rm8, self.instr.imm8)


    def sub_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 - self.instr.imm8)
        self.emu.update_eflags_sub(rm8, self.instr.imm8)


    def xor_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 ^ self.instr.imm8)


    def cmp_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.emu.update_eflags_sub(rm8, self.emu.constant(self.instr.imm8, Type.int_8))


    def shl_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 << self.instr.imm8)
        self.emu.update_eflags_shl(rm8, self.emu.constant(self.instr.imm8, Type.int_8))


    def shr_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(rm8 >> self.instr.imm8)
        self.emu.update_eflags_shr(rm8, self.instr.imm8)


    def sal_rm8_imm8(self) -> None:
        rm8_s = self.get_rm8().signed
        self.set_rm8(rm8_s << self.instr.imm8)


    def sar_rm8_imm8(self) -> None:
        rm8_s = self.get_rm8()
        self.set_rm8(rm8_s.sar(self.instr.imm8))


    def test_rm8_imm8(self) -> None:
        rm8 = self.get_rm8()
        imm8 = self.instr.imm8  #self.emu.get_code8(0)
        #self.emu.update_eip(1)
        self.emu.update_eflags_and(rm8, imm8)


    def not_rm8(self) -> None:
        rm8 = self.get_rm8()
        self.set_rm8(~rm8)


    def neg_rm8(self) -> None:
        rm8_s = self.get_rm8().signed
        self.set_rm8(-rm8_s)
        self.emu.update_eflags_sub(0, rm8_s)


    def mul_ax_al_rm8(self) -> None:
        rm8 = self.get_rm8()
        al = self.emu.get_gpreg(reg8_t.AL)
        val = al * rm8
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
