from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pyvex.lifting.util.vex_helper import Type

from .ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from .regs import reg16_t, reg32_t, sgreg_t


def operand_width_bits(mode32: bool, chsz_op: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_op) else 16


def address_width_bits(mode32: bool, chsz_ad: bool = False) -> int:
    return 32 if mode32 ^ bool(chsz_ad) else 16


@dataclass(frozen=True)
class WidthProfile:
    operand_bits: int
    address_bits: int

    @property
    def operand_bytes(self) -> int:
        return self.operand_bits // 8

    @property
    def address_bytes(self) -> int:
        return self.address_bits // 8


def decode_width_profile(mode32: bool, chsz_op: bool = False, chsz_ad: bool = False) -> WidthProfile:
    return WidthProfile(
        operand_bits=operand_width_bits(mode32, chsz_op),
        address_bits=address_width_bits(mode32, chsz_ad),
    )


@dataclass(frozen=True)
class DecodeWidthMatrixCase:
    name: str
    mode32: bool
    chsz_op: bool
    chsz_ad: bool
    profile: WidthProfile


DECODE_WIDTH_MATRIX: tuple[DecodeWidthMatrixCase, ...] = (
    DecodeWidthMatrixCase("16/16", False, False, False, decode_width_profile(False, False, False)),
    DecodeWidthMatrixCase("32/16", False, True, False, decode_width_profile(False, True, False)),
    DecodeWidthMatrixCase("16/32", False, False, True, decode_width_profile(False, False, True)),
    DecodeWidthMatrixCase("32/32", True, False, False, decode_width_profile(True, False, False)),
)


def decode_width_case(mode32: bool, chsz_op: bool = False, chsz_ad: bool = False) -> DecodeWidthMatrixCase:
    for case in DECODE_WIDTH_MATRIX:
        if case.mode32 == mode32 and case.chsz_op == chsz_op and case.chsz_ad == chsz_ad:
            return case
    raise ValueError(f"unsupported width case: mode32={mode32} chsz_op={chsz_op} chsz_ad={chsz_ad}")


def decode_width_case_for_profile(operand_bits: int, address_bits: int) -> DecodeWidthMatrixCase:
    for case in DECODE_WIDTH_MATRIX:
        if case.profile.operand_bits == operand_bits and case.profile.address_bits == address_bits:
            return case
    raise ValueError(f"unsupported width profile: operand_bits={operand_bits} address_bits={address_bits}")


def displacement_width_bits(mod: int, rm: int, address_bits: int) -> int | None:
    if address_bits == 16:
        if mod == 0 and rm == 6:
            return 16
        if mod == 1:
            return 8
        if mod == 2:
            return 16
        return None
    if mod == 0 and rm == 5:
        return 32
    if mod == 1:
        return 8
    if mod == 2:
        return 32
    return None


def signed_displacement(value: int, width_bits: int) -> int:
    mask = (1 << width_bits) - 1
    value &= mask
    sign_bit = 1 << (width_bits - 1)
    if value & sign_bit:
        return value - (1 << width_bits)
    return value


def type_for_bits(width_bits: int):
    if width_bits == 8:
        return Type.int_8
    if width_bits == 16:
        return Type.int_16
    if width_bits == 32:
        return Type.int_32
    raise ValueError(f"unsupported width: {width_bits}")


def address_step(emu, step_bytes: int, address_bits: int = 16):
    return emu.constant(step_bytes, type_for_bits(address_bits))


def describe_x86_16_decode_width_matrix() -> tuple[tuple[str, int, int], ...]:
    return tuple((case.name, case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX)


def describe_x86_16_mixed_width_extension_surface() -> dict[str, object]:
    return {
        "matrix": tuple(
            {
                "name": case.name,
                "operand_bits": case.profile.operand_bits,
                "address_bits": case.profile.address_bits,
                "mode32": case.mode32,
                "chsz_op": case.chsz_op,
                "chsz_ad": case.chsz_ad,
            }
            for case in DECODE_WIDTH_MATRIX
        ),
        "supported_pairs": tuple((case.profile.operand_bits, case.profile.address_bits) for case in DECODE_WIDTH_MATRIX),
        "address_widths": tuple(sorted({case.profile.address_bits for case in DECODE_WIDTH_MATRIX})),
        "operand_widths": tuple(sorted({case.profile.operand_bits for case in DECODE_WIDTH_MATRIX})),
    }


def describe_x86_16_mixed_width_instruction_surface() -> dict[str, object]:
    return {
        "boundary": "mixed-width decode facts feed shared helpers instead of handler-local branches",
        "consumer_paths": (
            "angr_platforms/X86_16/parse.py",
            "angr_platforms/X86_16/exec.py",
            "angr_platforms/X86_16/instruction.py",
            "angr_platforms/X86_16/instr16.py",
            "angr_platforms/X86_16/instr32.py",
        ),
        "validated_by": (
            "tests/test_x86_16_addressing_helpers.py",
            "tests/test_x86_16_decode_metadata.py",
            "tests/test_x86_16_instruction_core_factoring.py",
        ),
        "matrix": describe_x86_16_mixed_width_extension_surface()["matrix"],
    }


def linear_address(emu, segment, offset):
    # EXECUTION ONLY. Forbidden for alias/type/rewrite semantics.
    return emu.v2p(segment, offset)


def resolve_memory_operand_8616(
    emu,
    seg,
    addr,
    width_bits: int,
    *,
    address_bits: int = 16,
) -> "ResolvedMemoryOperand":
    # EXECUTION ONLY: exec_linear is computed for the engine, not for semantics.
    # Alias/type/structuring layers MUST use operand.ir_address() instead.
    if isinstance(seg, sgreg_t) and seg == sgreg_t.SS:
        exec_linear = emu.convert_ss_vaddr(addr)
    else:
        exec_linear = emu.v2p(seg, addr)
    return ResolvedMemoryOperand(seg, addr, exec_linear, width_bits, address_bits)


@dataclass(frozen=True)
class ResolvedMemoryOperand:
    segment: sgreg_t
    offset: Any
    exec_linear: Any
    width_bits: int
    address_bits: int

    @property
    def linear(self) -> Any:
        """Deprecated: use exec_linear for execution-only linear address.
        
        This property exists only for backward compatibility.
        Forbidden for alias/type/rewrite semantics — use ir_address() instead.
        """
        return self.exec_linear

    def ir_address(self, *, expr: tuple[str, ...] | None = None) -> IRAddress:
        """Semantic IR address — the ONLY path for alias/type/structuring layers."""
        return self.typed_address(expr=expr)

    def assert_semantic_safe(self) -> None:
        """Block accidental use of linear address in semantic layers.

        Raises PipelineHardError if exec_linear leaks into non-execution code.
        AGENTS rule #3: segmented memory; exec_linear is execution-only.
        """
        from .ir.core import IRAddress
        from .pipeline.errors import PipelineHardError
        if isinstance(self.exec_linear, IRAddress):
            raise PipelineHardError(
                "exec_linear must not be an IRAddress — linear is execution-only, "
                "use ir_address() for semantic layers",
                layer="addressing",
            )

    def typed_address(self, *, expr: tuple[str, ...] | None = None) -> IRAddress:
        space_map = {
            sgreg_t.SS: MemSpace.SS,
            sgreg_t.DS: MemSpace.DS,
            sgreg_t.ES: MemSpace.ES,
            sgreg_t.CS: MemSpace.UNKNOWN,
            MemSpace.SS: MemSpace.SS,
            MemSpace.DS: MemSpace.DS,
            MemSpace.ES: MemSpace.ES,
            MemSpace.UNKNOWN: MemSpace.UNKNOWN,
        }
        space = space_map.get(self.segment, MemSpace.UNKNOWN)
        explicit_segment = isinstance(self.segment, (sgreg_t, MemSpace)) and space != MemSpace.UNKNOWN
        stable = explicit_segment and space in {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        if isinstance(self.segment, sgreg_t):
            base = (self.segment.name.lower(),)
        elif isinstance(self.segment, MemSpace) and self.segment != MemSpace.UNKNOWN:
            base = (self.segment.value,)
        else:
            base = ()

        size = max(1, self.width_bits // 8) if isinstance(self.width_bits, int) and self.width_bits > 0 else 0
        seg_origin = SegmentOrigin.PROVEN if explicit_segment else (SegmentOrigin.DEFAULTED if space != MemSpace.UNKNOWN else SegmentOrigin.UNKNOWN)

        # Unwrap VexValue wrapper and resolve RdTmp chain via IRSB
        offset_raw = self.offset
        tmp_defs = None
        if hasattr(self.offset, "rdt"):
            offset_raw = self.offset.rdt
            irsb_c = getattr(self.offset, "irsb_c", None)
            if irsb_c is not None:
                tmp_defs = _build_tmp_defs_from_irsb(irsb_c)
                offset_raw = _resolve_rdtmp_chain(offset_raw, tmp_defs)

        # Integer offset
        if isinstance(offset_raw, int):
            # IMPORTANT:
            # SS memory activity is not automatically a stack variable.
            #
            # The following are intentionally PROVISIONAL:
            #   - push/pop traffic
            #   - transient SP movement
            #   - call frame setup
            #   - unresolved symbolic SP expressions
            #
            # Only proven frame-relative accesses
            # (BP+const or proven SP+stable_delta+const)
            # may become STABLE stack slots.
            #
            # AGENTS rule:
            # stack activity != materializable variable
            if space == MemSpace.SS:
                if not base:
                    base = ("ss",)
                return IRAddress(
                    space=space,
                    base=base,
                    offset=offset_raw,
                    size=size,
                    status=AddressStatus.PROVISIONAL,
                    segment_origin=seg_origin,
                    expr=expr,
                )
            # DS/ES:int — stable memory address
            return IRAddress(
                space=space,
                base=base,
                offset=offset_raw,
                size=size,
                status=AddressStatus.STABLE if stable else AddressStatus.PROVISIONAL,
                segment_origin=seg_origin,
                expr=expr,
            )

        # Symbolic offset — try to extract BP-relative constant
        extracted = extract_bp_relative_offset_8616(offset_raw, tmp_defs=tmp_defs)
        if extracted is not None:
            offset_val, bp_base = extracted
            # BP-relative stack slot: STABLE status, base = ("bp",)
            if space == MemSpace.SS:
                base = ("bp",)
            return IRAddress(
                space=space,
                base=base,
                offset=offset_val,
                size=size,
                status=AddressStatus.STABLE,
                segment_origin=seg_origin,
                expr=None,
            )

        # Not BP-relative: return PROVISIONAL — do NOT fake offset 0
        return IRAddress(
            space=space,
            base=base,
            offset=0,
            size=size,
            status=AddressStatus.PROVISIONAL,
            segment_origin=seg_origin,
            expr=(str(self.offset),) if self.offset is not None else expr,
        )


def default_segment_for_modrm16(mod: int, rm: int) -> sgreg_t:
    if rm in (2, 3):
        return sgreg_t.SS
    if rm == 6 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def default_segment_for_modrm32(mod: int, rm: int, sib_base: int | None = None) -> sgreg_t:
    if rm == 4 and sib_base is not None:
        if sib_base in (4, 5):
            return sgreg_t.SS
        return sgreg_t.DS
    if rm == 5 and mod != 0:
        return sgreg_t.SS
    return sgreg_t.DS


def modrm16_effective_offset(emu, modrm, disp8: int, disp16: int):
    addr = emu.constant(0, Type.int_16)

    if modrm.mod == 1:
        addr = addr + emu.constant(signed_displacement(disp8, 8) & 0xFFFF, Type.int_16)
    elif modrm.mod == 2:
        addr = addr + emu.constant(disp16, Type.int_16)

    rm = modrm.rm
    if rm in (0, 1, 7):
        addr = addr + emu.get_gpreg(reg16_t.BX)
    elif rm in (2, 3, 6):
        if modrm.mod == 0 and rm == 6:
            addr = addr + emu.constant(disp16, Type.int_16)
        else:
            addr = addr + emu.get_gpreg(reg16_t.BP)

    if rm < 6:
        if rm % 2:
            addr = addr + emu.get_gpreg(reg16_t.DI)
        else:
            addr = addr + emu.get_gpreg(reg16_t.SI)

    return addr


def modrm32_effective_offset(emu, modrm, sib, disp8: int, disp32: int):
    addr = emu.constant(0, Type.int_32)

    if modrm.mod == 1:
        addr = addr + emu.constant(signed_displacement(disp8, 8) & 0xFFFFFFFF, Type.int_32)
    elif modrm.mod == 2:
        addr = addr + emu.constant(disp32, Type.int_32)

    rm = modrm.rm
    if rm == 4:
        if sib.base == 5 and modrm.mod == 0:
            base = emu.constant(disp32, Type.int_32)
        elif sib.base == 4:
            base = emu.get_gpreg(reg32_t.ESP)
        else:
            base = emu.get_gpreg(reg32_t(sib.base))
        if sib.index == 4:
            index = emu.constant(0, Type.int_32)
        else:
            index = emu.get_gpreg(reg32_t(sib.index))
        addr = addr + base + index * (1 << sib.scale)
        return addr

    if rm == 5 and modrm.mod == 0:
        return addr + emu.constant(disp32, Type.int_32)
    return addr + emu.get_gpreg(reg32_t(rm))


def resolve_modrm16_address(emu, modrm, disp8: int, disp16: int) -> tuple[sgreg_t, Any]:
    segment = default_segment_for_modrm16(modrm.mod, modrm.rm)
    return segment, modrm16_effective_offset(emu, modrm, disp8, disp16)


def resolve_modrm32_address(emu, modrm, sib, disp8: int, disp32: int) -> tuple[sgreg_t, Any]:
    segment = default_segment_for_modrm32(modrm.mod, modrm.rm, sib.base if modrm.rm == 4 else None)
    return segment, modrm32_effective_offset(emu, modrm, sib, disp8, disp32)


def resolve_linear_operand(emu, segment: sgreg_t, offset, width_bits: int, address_bits: int) -> ResolvedMemoryOperand:
    # EXECUTION ONLY
    return ResolvedMemoryOperand(segment, offset, linear_address(emu, segment, offset), width_bits, address_bits)


def load_resolved_operand(emu, operand: ResolvedMemoryOperand):
    if operand.width_bits == 8:
        return emu.get_data8(operand.segment, operand.offset)
    if operand.width_bits == 16:
        return emu.get_data16(operand.segment, operand.offset)
    if operand.width_bits == 32:
        return emu.get_data32(operand.segment, operand.offset)
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def store_resolved_operand(emu, operand: ResolvedMemoryOperand, value) -> None:
    if operand.width_bits == 8:
        emu.put_data8(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 16:
        emu.put_data16(operand.segment, operand.offset, value)
        return
    if operand.width_bits == 32:
        emu.put_data32(operand.segment, operand.offset, value)
        return
    raise ValueError(f"unsupported resolved operand width: {operand.width_bits}")


def load_word_pair16(emu, segment: sgreg_t, offset, address_bits: int = 16):
    if isinstance(offset, int):
        offset = emu.constant(offset, type_for_bits(address_bits))
    step = address_step(emu, 2, address_bits)
    first = emu.get_data16(segment, offset)
    second = emu.get_data16(segment, offset + step)
    return first, second


def load_far_pointer(emu, segment: sgreg_t, offset, operand_bits: int, address_bits: int = 16):
    if isinstance(offset, int):
        offset = emu.constant(offset, type_for_bits(address_bits))
    step = address_step(emu, operand_bits // 8, address_bits)
    if operand_bits == 16:
        far_offset = emu.get_data16(segment, offset)
    elif operand_bits == 32:
        far_offset = emu.get_data32(segment, offset)
    else:
        raise ValueError(f"unsupported far pointer operand width: {operand_bits}")
    far_segment = emu.get_data16(segment, offset + step)
    return far_offset, far_segment


def load_far_pointer16(emu, segment: sgreg_t, offset, address_bits: int = 16):
    return load_word_pair16(emu, segment, offset, address_bits=address_bits)


def _build_tmp_defs_from_irsb(irsb_c) -> dict[int, Any]:
    """Build a tmp_index → WrTmp statement mapping from an IRSB or IRSBCustomizer."""
    tmp_defs = {}
    if irsb_c is None:
        return tmp_defs
    # Unwrap IRSBCustomizer to underlying IRSB
    irsb = getattr(irsb_c, "irsb", irsb_c)
    stmts = getattr(irsb, "statements", None) or ()
    for stmt in stmts:
        stmt_tmp = getattr(stmt, "tmp", None)
        if isinstance(stmt_tmp, int):
            tmp_defs[stmt_tmp] = stmt
    return tmp_defs


def _resolve_rdtmp_chain(expr: Any, tmp_defs: dict) -> Any:
    """Resolve RdTmp nodes to their defining expressions, recursively."""
    if not isinstance(tmp_defs, dict) or not tmp_defs:
        return expr

    class_name = getattr(type(expr), "__name__", "")
    if "RdTmp" in class_name:
        tmp_idx = getattr(expr, "tmp", None)
        if isinstance(tmp_idx, int) and tmp_idx in tmp_defs:
            stmt = tmp_defs[tmp_idx]
            stmt_expr = getattr(stmt, "data", None)
            if stmt_expr is not None:
                # Recursively resolve — the defining expression may contain RdTmps too
                return _resolve_rdtmp_chain(stmt_expr, tmp_defs)

    # For Binop/Unop/etc, resolve args recursively
    args = getattr(expr, "args", None)
    if args is not None:
        resolved_args = [_resolve_rdtmp_chain(a, tmp_defs) for a in args]
        if resolved_args != list(args):
            new_expr = type(expr)(getattr(expr, "op", None), resolved_args)
            return new_expr

    return expr


def extract_bp_relative_offset_8616(offset_expr: Any, *, tmp_defs: dict | None = None) -> tuple[int, tuple[str, ...]] | None:
    """Extract a BP-relative constant offset from a symbolic offset expression.

    Handles only proven forms:
        BP + const
        BP - const
        const + BP
        BP
        BP + SI/DI + const
        BP + SI/DI - const

    Returns (offset, base_tuple) or None.
    Does NOT guess for BX+SI, SP+unknown, tmp, or other complex forms.
    """
    # Resolve RdTmp → defining expression if tmp_defs available
    if tmp_defs is not None:
        offset_expr = _resolve_rdtmp_chain(offset_expr, tmp_defs)

    # Integer offset: pass through
    if isinstance(offset_expr, int):
        return (offset_expr, ("bp",))

    # VEX expression: try to match BP +/- const pattern
    op = getattr(offset_expr, "op", None)
    if op is None:
        return None

    op_str = str(op)
    args = getattr(offset_expr, "args", None) or []

    if len(args) < 2:
        # Unary or single-arg — check if it's just BP
        for arg in args:
            if _is_bp_reg(arg, tmp_defs=tmp_defs):
                return (0, ("bp",))
        return None

    # Flatten nested Add/Sub chains into terms
    terms, const = _collect_add_sub_terms(offset_expr, tmp_defs=tmp_defs)
    if terms is None:
        # Fallback to simple 2-arg patterns
        left, right = args[0], args[1]
        if op_str in {"Iop_Add16", "Iop_Add32"}:
            if _is_bp_reg(left, tmp_defs=tmp_defs) and isinstance(right, int):
                return (right & 0xFFFF, ("bp",))
            if isinstance(left, int) and _is_bp_reg(right, tmp_defs=tmp_defs):
                return (left & 0xFFFF, ("bp",))
        if op_str in {"Iop_Sub16", "Iop_Sub32"}:
            if _is_bp_reg(left, tmp_defs=tmp_defs) and isinstance(right, int):
                return (-(right & 0xFFFF), ("bp",))
        return None

    # Accept: BP (+ SI/DI) + const
    has_bp = any(_is_bp_reg(term, tmp_defs=tmp_defs) for term in terms)
    has_index = any(_is_index_reg_8616(term) for term in terms)
    non_reg_terms = [t for t in terms if not _is_bp_reg(t, tmp_defs=tmp_defs) and not _is_index_reg_8616(t)]

    if has_bp and not non_reg_terms:
        # BP only or BP + index: accept
        return (const & 0xFFFF, ("bp",))

    return None


def _collect_add_sub_terms(
    expr: Any,
    *,
    tmp_defs: dict | None = None,
) -> tuple[list[Any], int] | None:
    """Flatten Iop_Add16/Add32 and Iop_Sub16/Sub32 chains.

    Returns (non_constant_terms, constant_total) or None if unsupported.
    Constant terms are summed into the constant_total.
    Sub-expressions in Sub positions negate their constant contribution.
    """
    # Resolve RdTmp chains through tmp_defs first
    if tmp_defs is not None:
        expr = _resolve_rdtmp_chain(expr, tmp_defs)

    op = getattr(expr, "op", None)
    if op is None:
        # Leaf expression: VEX Get, RdTmp, Const, or int literal.
        # These are atomic terms — return them as a single-term list.
        # Handle VEX Const objects (tag=Iex_Const, .con.value)
        tag = getattr(expr, "tag", None)
        if tag == "Iex_Const":
            con = getattr(expr, "con", None)
            if con is not None:
                val = getattr(con, "value", None)
                if isinstance(val, int):
                    return ([], val & 0xFFFF)
        if isinstance(expr, int):
            return ([], expr & 0xFFFF)
        return ([expr], 0)

    op_str = str(op)
    args = getattr(expr, "args", None) or []
    if not args:
        return None

    if op_str in {"Iop_Add16", "Iop_Add32"}:
        left_res = _collect_add_sub_terms(args[0], tmp_defs=tmp_defs)
        right_res = _collect_add_sub_terms(args[1], tmp_defs=tmp_defs)
        if left_res is None or right_res is None:
            return ([args[0], args[1]], 0)
        left_terms, left_const = left_res
        right_terms, right_const = right_res
        if left_terms is not None and right_terms is not None:
            return (left_terms + right_terms, (left_const + right_const) & 0xFFFF)
        # One side may be non-decomposable; treat it as a term
        if left_terms is not None:
            return (left_terms + [args[1]], left_const & 0xFFFF)
        if right_terms is not None:
            return (right_terms + [args[0]], right_const & 0xFFFF)
        return ([args[0], args[1]], 0)

    if op_str in {"Iop_Sub16", "Iop_Sub32"}:
        left_res = _collect_add_sub_terms(args[0], tmp_defs=tmp_defs)
        right_res = _collect_add_sub_terms(args[1], tmp_defs=tmp_defs)
        if left_res is None or right_res is None:
            return ([args[0], args[1]], 0)
        left_terms, left_const = left_res
        right_terms, right_const = right_res
        if left_terms is not None and right_terms is not None:
            return (left_terms + right_terms, (left_const - right_const) & 0xFFFF)
        if left_terms is not None:
            return (left_terms + [args[1]], left_const & 0xFFFF)
        if right_terms is not None:
            return (right_terms + [args[0]], (-right_const) & 0xFFFF)
        return ([args[0], args[1]], 0)

    # Leaf: constant or register
        # Handle VEX Const objects (tag=Iex_Const, .con.value)
        tag = getattr(expr, "tag", None)
        if tag == "Iex_Const":
            con = getattr(expr, "con", None)
            if con is not None:
                val = getattr(con, "value", None)
                if isinstance(val, int):
                    return ([], val & 0xFFFF)
    if isinstance(expr, int):
        return ([], expr & 0xFFFF)
    reg_offset = getattr(expr, "reg", None)
    if isinstance(reg_offset, int):
        return ([expr], 0)

    return None


def _is_index_reg_8616(expr: Any) -> bool:
    """Check if a VEX expression is SI or DI.

    VEX guest state offsets (from archinfo arch_from_id('x86_16')):
      si → offset=32
      di → offset=36
    The reg16_t enum values (SI=6, DI=7) are NOT VEX guest offsets.
    """
    class_name = getattr(type(expr), "__name__", "")
    if "Get" in class_name:
        offset = getattr(expr, "offset", None)
        if isinstance(offset, int) and offset in {12, 14, 32, 36}:
            return True

    # Obsolete path: reg16_t enum values (never matched VEX expressions)
    reg_offset = getattr(expr, "reg", None)
    if isinstance(reg_offset, int) and reg_offset in {6, 7}:
        return True

    return False


def _is_bp_reg(expr: Any, *, tmp_defs: dict | None = None) -> bool:
    """Check if a VEX expression is a BP register reference.

    BP appears as:
      - Get(offset=28, ...)   — VEX guest state offset for bp (archinfo arch_from_id('x86_16'))
      - RdTmp(tmp=N) when tmp_defs maps N → WrTmp(..., Get(offset=28, ...))

    The old reg16_t enum value 5 is NOT a VEX guest offset — that was a bug.
    """
    class_name = getattr(type(expr), "__name__", "")

    # RdTmp: resolve through tmp_defs if available
    if "RdTmp" in class_name and tmp_defs is not None:
        tmp_idx = getattr(expr, "tmp", None)
        if isinstance(tmp_idx, int):
            stmt = tmp_defs.get(tmp_idx)
            if stmt is not None:
                stmt_expr = getattr(stmt, "data", None) or getattr(stmt, "expr", None)
                if stmt_expr is not None:
                    return _is_bp_reg(stmt_expr, tmp_defs=tmp_defs)

    # Direct Get node: VEX guest state offset 28 = bp
    if "Get" in class_name:
        offset = getattr(expr, "offset", None)
        if isinstance(offset, int) and offset in {10, 28}:
            return True

    # Obsolete path: reg16_t enum value (never matched VEX expressions)
    reg_offset = getattr(expr, "reg", None)
    if isinstance(reg_offset, int) and reg_offset == 5:
        return True

    return False


def advance_ip16(emu, byte_count: int):
    return emu.get_gpreg(reg16_t.IP) + emu.constant(byte_count, Type.int_16)


def advance_eip32(emu, byte_count: int):
    return emu.get_gpreg(reg32_t.EIP) + emu.constant(byte_count, Type.int_32)
