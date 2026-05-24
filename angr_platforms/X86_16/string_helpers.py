from __future__ import annotations

from pyvex.lifting.util import JumpKind
from pyvex.lifting.util.vex_helper import Type

from .alu_helpers import compare_operation
from .instruction import REPNZ, REPZ
from .regs import reg16_t, reg32_t, sgreg_t


def string_delta(emu, width: int):
    df = emu.is_direction()
    neg = emu.constant((-width) & 0xFFFF, Type.int_16)
    pos = emu.constant(width, Type.int_16)
    expr = emu.lifter_instruction.irsb_c.ite(df.cast_to(Type.int_1).rdt, neg.rdt, pos.rdt)
    return emu._vv(expr)


def string_source_segment(instr) -> sgreg_t:
    if instr.pre_segment is not None:
        return sgreg_t(instr.pre_segment)
    return sgreg_t.DS


def repeat_kind(instr) -> str:
    normalized = getattr(instr, "repeat_class", None)
    if normalized not in (None, ""):
        return normalized
    if instr.pre_repeat == REPZ:
        return "repz"
    if instr.pre_repeat == REPNZ:
        return "repnz"
    return "none"


def repeat_prefix_cond(emu, instr):
    if repeat_kind(instr) == "none":
        return None

    cx = emu.get_gpreg(reg16_t.CX)
    remaining = cx - emu.constant(1, Type.int_16)
    emu.set_gpreg(reg16_t.CX, remaining)
    return remaining != emu.constant(0, Type.int_16)


def repeat_jump(emu, instr, repeat_cond, zf_sensitive: bool = False) -> None:
    if repeat_cond is None:
        return

    cond = repeat_cond.cast_to(Type.int_1)
    if zf_sensitive:
        kind = repeat_kind(instr)
        if kind == "repz":
            cond = cond & emu.is_zero()
        elif kind == "repnz":
            cond = cond & (emu.is_zero() == emu.constant(0, Type.int_1))
    if isinstance(cond, bool):
        if not cond:
            return
        ip_reg = reg32_t.EIP if getattr(instr, "mode32", False) else reg16_t.IP
        repeat_target = emu.get_gpreg(ip_reg)
        repeat_target_expr = repeat_target.rdt if hasattr(repeat_target, "rdt") else repeat_target
        emu.lifter_instruction.jump(None, repeat_target_expr, JumpKind.Boring)
        emu.set_gpreg(ip_reg, repeat_target)
        return
    cond_value = getattr(cond, "rdt", None)
    ip_reg = reg32_t.EIP if getattr(instr, "mode32", False) else reg16_t.IP
    repeat_target = emu.get_gpreg(ip_reg)
    repeat_target_expr = repeat_target.rdt if hasattr(repeat_target, "rdt") else repeat_target

    if isinstance(cond_value, bool):
        if not cond_value:
            return
        emu.lifter_instruction.jump(None, repeat_target_expr, JumpKind.Boring)
        emu.set_gpreg(ip_reg, repeat_target)
        return

    emu.lifter_instruction.jump(cond, repeat_target_expr, JumpKind.Boring)
    emu.set_gpreg(ip_reg, repeat_target)


def string_advance_indices(emu, width: int, *regs) -> object:
    delta = string_delta(emu, width)
    for reg in regs:
        emu.set_gpreg(reg, emu.get_gpreg(reg) + delta)
    return delta


def string_compare_values(lhs, rhs, update_flags) -> None:
    compare_operation(lambda: lhs, lambda: rhs, update_flags)


def string_load(emu, segment: sgreg_t, offset, width: int):
    if width == 1:
        return emu.get_data8(segment, offset)
    if width == 2:
        return emu.get_data16(segment, offset)
    if width == 4:
        return emu.get_data32(segment, offset)
    raise ValueError(f"unsupported string width: {width}")


def string_store(emu, segment: sgreg_t, offset, value, width: int) -> None:
    if width == 1:
        emu.put_data8(segment, offset, value)
        return
    if width == 2:
        emu.put_data16(segment, offset, value)
        return
    if width == 4:
        emu.put_data32(segment, offset, value)
        return
    raise ValueError(f"unsupported string width: {width}")
