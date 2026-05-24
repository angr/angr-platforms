"""Stack frame recovery — detects BP-frame usage and normalizes stack accesses.

AGENTS rule: SS:BP+offset → stack slot → variable (REQUIRED).
This must happen BEFORE alias sees the IR addresses.

Pipeline position:
    IR (raw) → stack_frame_recovery → normalized IR → Alias

Frame models:
    BP frame:  push bp; mov bp,sp; sub sp,N  — SS:BP+offset → STABLE stack slot
    SP frame:  sub sp,N  (no BP)            — SS:SP+offset → PROVISIONAL (no derived BP)
    none:      no SS accesses                — no stack

Rule:
    BP + constant         → STABLE stack slot
    SP + known delta      → STABLE stack slot
    raw SP / push / call  → PROVISIONAL stack access (DO NOT invent BP)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Any

from ..ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin
from ..pipeline.errors import PipelineHardError


@dataclass(frozen=True)
class StackFrameInfo8616:
    function_addr: int | None
    uses_bp_frame: bool = False
    uses_sp_frame: bool = False
    bp_established: bool = False
    sp_delta_known: bool = False
    frame_base: str | None = None
    frame_kind: str = "none"
    evidence: tuple[str, ...] = ()


def _is_ss(addr: object) -> bool:
    return isinstance(addr, IRAddress) and addr.space == MemSpace.SS


def _is_bp_stable(addr: IRAddress) -> bool:
    return (
        addr.space == MemSpace.SS
        and addr.base == ("bp",)
        and isinstance(addr.offset, int)
        and addr.status == AddressStatus.STABLE
    )


def _is_sp_stable(addr: IRAddress) -> bool:
    """SP+known_delta must be proven upstream — not guessed here."""
    return (
        addr.space == MemSpace.SS
        and addr.base == ("sp",)
        and isinstance(addr.offset, int)
        and addr.status == AddressStatus.STABLE
    )


def _count_ss_accesses(semantic_accesses: Iterable) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_ss(addr):
            n += 1
    return n


def _count_sp_provisional(semantic_accesses: Iterable) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_ss(addr) and addr.status == AddressStatus.PROVISIONAL and addr.base != ("bp",):
            n += 1
    return n


def _count_sp_stable(semantic_accesses: Iterable) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_sp_stable(addr):
            n += 1
    return n


def _count_bp_stable(semantic_accesses: Iterable) -> int:
    n = 0
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_bp_stable(addr):
            n += 1
    return n


def _has_any_bp_base(semantic_accesses: Iterable) -> bool:
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_ss(addr) and addr.base == ("bp",):
            return True
    return False


def _has_any_sp_stable(semantic_accesses: Iterable) -> bool:
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", None)
        if _is_sp_stable(addr):
            return True
    return False


def _looks_like_frame_evidence(obj: object) -> bool:
    """Check for BP frame evidence using structured IR artifacts, NOT text parsing.

    Accepts CapstoneInsn objects (already-parsed structured disassembly)
    or VEX IRSB objects.  Rejects plain strings / COD text.
    """

    import sys
    sys.stderr.flush()

    # ── Capstone instruction (structured, NOT text) ──
    mnemonic = getattr(obj, "mnemonic", None)
    if mnemonic is not None:
        mnem_str = str(mnemonic).lower()
        operands = getattr(obj, "operands", None) or []

        # push bp — register-based detection using capstone reg IDs
        if mnem_str == "push":
            for op in operands:
                reg_val = getattr(op, "reg", None)
                if isinstance(reg_val, int) and reg_val == 6:  # X86_REG_BP = 6
                    return True

        # mov bp, sp
        elif mnem_str == "mov":
            if len(operands) >= 2:
                dst_reg = getattr(operands[0], "reg", None)
                src_reg = getattr(operands[1], "reg", None)
                if isinstance(dst_reg, int) and dst_reg == 6 and isinstance(src_reg, int) and src_reg == 47:
                    return True

        return False

    # ── VEX IRSB (direct) — check statement tags for push-bp / mov-bp-sp ──
    statements = getattr(obj, "statements", None)
    if statements is not None:
        return _vex_irsb_has_bp_frame(obj)

    # ── angr Block — iterate capstone instructions for frame patterns ──
    capstone = getattr(obj, "capstone", None)
    if capstone is not None:
        insns = getattr(capstone, "insns", None)
        if insns is not None:
            for insn in insns:
                if _looks_like_frame_evidence(insn):
                    return True

    # ── Reject string/COD artifacts ──
    if isinstance(obj, str):
        return False

    return False


def _vex_irsb_has_bp_frame(irsb) -> bool:
    """Inspect VEX IRSB statements for BP frame setup patterns.

    push bp  → Ist_Store(base=SS*16+SP-2, data=GET(BP))  after  Ist_Put(SP)=SUB(GET(SP), 2)
    mov bp,sp → Ist_Put(BP) = GET(SP)
    """
    has_push_bp = False
    has_mov_bp_sp = False

    try:
        arch = getattr(irsb, "arch", None)
        if arch is None:
            return False
        sp_off = getattr(arch, "sp_offset", None)
        bp_off = getattr(arch, "bp_offset", None)
        if sp_off is None or bp_off is None:
            return False
    except Exception:
        return False

    for stmt in getattr(irsb, "statements", ()) or ():
        tag = getattr(stmt, "tag", "")
        if tag == "Ist_Put":
            put_off = getattr(stmt, "offset", None)
            data = getattr(stmt, "data", None)
            if put_off == bp_off and data is not None:
                # PUT(BP) = GET(SP)  →  mov bp, sp
                if _is_reg_get(data, sp_off):
                    has_mov_bp_sp = True
            elif put_off == sp_off and data is not None:
                # PUT(SP) = SUB(GET(SP), 2)  →  sub sp, 2 (push)
                if _is_sub_constant(data, 2):
                    has_push_bp = True

    return has_push_bp and has_mov_bp_sp


def _is_reg_get(vex_expr, reg_offset: int) -> bool:
    """True when vex_expr is a pure GET(reg_offset)."""
    if getattr(vex_expr, "tag", "") != "Iex_Get":
        return False
    return getattr(vex_expr, "offset", None) == reg_offset


def _is_sub_constant(vex_expr, constant: int) -> bool:
    """True when vex_expr is Binop(Sub, Iex_Get(...), Iex_Const(constant))."""
    if getattr(vex_expr, "tag", "") != "Iex_Binop":
        return False
    if str(getattr(vex_expr, "op", "")) not in ("Iop_Sub32", "Iop_Sub16"):
        return False
    rhs = getattr(vex_expr, "child_expressions", None)
    if rhs is None:
        return False
    try:
        const_expr = rhs[1]  # type: ignore[index]
    except (IndexError, TypeError):
        return False
    if getattr(const_expr, "tag", "") != "Iex_Const":
        return False
    const_val = getattr(const_expr, "con", None)
    return const_val is not None and getattr(const_val, "value", None) == constant


def _gather_ir_artifacts_from_function_blocks(project, function_addr: int) -> list[object]:
    """Collect angr Block objects for IR-based frame detection.

    Returns empty list if project/kb/function is unavailable.
    """
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is None:
        return []
    func = kb.functions.function(addr=function_addr, create=False)
    if func is None:
        return []
    artifacts: list[object] = []
    for blk in func.blocks:
        artifacts.append(blk)
    return artifacts


def _detect_sp_proven_delta_from_blocks(project, function_addr: int) -> int | None:
    """Detect proven SP delta from IR/VEX block analysis.

    Returns the SP delta (e.g. -8, -12) if proven, or None if not determinable.
    The delta is the function's frame size from ``sub sp, N`` after BP setup.
    
    Uses VEX IRSB statement analysis, NOT text parsing.
    """
    kb = getattr(project, "kb", None) if project is not None else None
    if kb is None:
        return None
    func = kb.functions.function(addr=function_addr, create=False)
    if func is None:
        return None

    # Gather all IRSBs for this function
    irsbs = []
    for blk in func.blocks:
        irsb = getattr(blk, "vex", None) or getattr(blk, "irsb", None)
        if irsb is not None:
            irsbs.append(irsb)

    if not irsbs:
        return None

    seen_bp_established = False
    sp_delta = None

    for irsb in irsbs:
        try:
            arch = getattr(irsb, "arch", None)
            if arch is None:
                continue
            sp_off = getattr(arch, "sp_offset", None)
            bp_off = getattr(arch, "bp_offset", None)
            if sp_off is None or bp_off is None:
                continue
        except Exception:
            continue

        for stmt in getattr(irsb, "statements", ()) or ():
            tag = getattr(stmt, "tag", "")
            if tag != "Ist_Put":
                continue

            put_off = getattr(stmt, "offset", None)
            data = getattr(stmt, "data", None)
            if put_off is None or data is None:
                continue

            # Detect mov bp, sp → BP frame established
            if put_off == bp_off and _is_reg_get(data, sp_off):
                seen_bp_established = True
                continue

            # Detect sub sp, N → compute frame size only AFTER BP established
            if seen_bp_established and put_off == sp_off:
                delta = _extract_sub_constant(data)
                if delta is not None and delta < 0:
                    sp_delta = delta
                    break  # first sub sp,N after mov bp,sp is the frame size

    return sp_delta


def _extract_sub_constant(vex_expr) -> int | None:
    """Extract the constant operand from SUB(GET(reg), Const(N)), returning N.

    Returns None if expression doesn't match SUB(binop) pattern.
    """
    if getattr(vex_expr, "tag", "") != "Iex_Binop":
        return None
    op_name = str(getattr(vex_expr, "op", ""))
    if "Sub" not in op_name:
        return None
    # Look for GET(reg) on left, Const on right
    try:
        args = getattr(vex_expr, "child_expressions", None)
        if args is None or len(args) < 2:
            return None
        lhs = args[0]
        rhs = args[1]
    except (IndexError, TypeError):
        return None

    if getattr(lhs, "tag", "") != "Iex_Get":
        return None
    if getattr(rhs, "tag", "") != "Iex_Const":
        return None
    const_val = getattr(rhs, "con", None)
    if const_val is None:
        return None
    value = getattr(const_val, "value", None)
    if isinstance(value, int):
        return -value  # SUB(X, N) → delta = -N
    return None


def detect_stack_frame_8616(
    *,
    function_addr: int | None = None,
    ir_artifacts: Iterable[object] = (),
    semantic_accesses: Iterable[tuple[int, IRAddress]] = (),
) -> StackFrameInfo8616:
    evidence: list[str] = []

    if _has_any_bp_base(semantic_accesses):
        evidence.append("ss:bp semantic access")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_bp_frame=True,
            bp_established=True,
            frame_base="bp",
            frame_kind="bp",
            evidence=tuple(evidence),
        )

    for artifact in ir_artifacts:
        if _looks_like_frame_evidence(artifact):
            evidence.append("frame setup instruction evidence")
            return StackFrameInfo8616(
                function_addr=function_addr,
                uses_bp_frame=True,
                bp_established=True,
                frame_base="bp",
                frame_kind="bp",
                evidence=tuple(evidence),
            )

    if _has_any_sp_stable(semantic_accesses):
        evidence.append("ss:sp stable semantic access (delta known)")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_sp_frame=True,
            sp_delta_known=True,
            frame_base="sp",
            frame_kind="sp",
            evidence=tuple(evidence),
        )

    ss_count = _count_ss_accesses(semantic_accesses)
    if ss_count > 0:
        evidence.append(f"ss:sp dynamic access (count={ss_count})")
        return StackFrameInfo8616(
            function_addr=function_addr,
            uses_sp_frame=True,
            sp_delta_known=False,
            frame_base="sp",
            frame_kind="sp",
            evidence=tuple(evidence),
        )

    return StackFrameInfo8616(
        function_addr=function_addr,
        frame_kind="none",
        evidence=(),
    )


def compute_bp_offset(addr: IRAddress, frame: StackFrameInfo8616) -> int | None:
    if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
        return None

    if not isinstance(addr.offset, int):
        return None

    if _is_bp_stable(addr):
        return addr.offset

    if _is_sp_stable(addr):
        return addr.offset

    if frame.uses_bp_frame and frame.bp_established:
        if addr.base in {("ss",), ("sp",), ()} and addr.status == AddressStatus.STABLE:
            return addr.offset

    return None


def normalize_stack_address_8616(addr: IRAddress, frame: StackFrameInfo8616) -> IRAddress:
    if not isinstance(addr, IRAddress):
        return addr

    if addr.space != MemSpace.SS:
        return addr

    if _is_bp_stable(addr):
        return addr

    if _is_sp_stable(addr):
        return addr

    if frame.uses_bp_frame and frame.bp_established:
        bp_offset = compute_bp_offset(addr, frame)
        if bp_offset is not None:
            return IRAddress(
                space=MemSpace.SS,
                base=("bp",),
                offset=bp_offset,
                size=addr.size,
                status=AddressStatus.STABLE,
                segment_origin=addr.segment_origin
                if addr.segment_origin is not None
                else SegmentOrigin.PROVEN,
                expr=addr.expr,
            )

    return addr


def normalize_semantic_accesses_8616(
    semantic_accesses: Iterable,
    frame: StackFrameInfo8616,
) -> list[tuple[int, IRAddress]]:
    normalized: list[tuple[int, IRAddress]] = []
    for acc in semantic_accesses:
        mode = getattr(acc, "mode", 0)
        addr = getattr(acc, "addr", None)
        if isinstance(addr, IRAddress):
            addr = normalize_stack_address_8616(addr, frame)
        normalized.append((mode, addr))
    return normalized


def assert_no_unresolved_stable_ss_before_alias_8616(
    semantic_accesses: Iterable,
) -> None:
    for acc in semantic_accesses:
        addr = getattr(acc, "addr", acc[1] if isinstance(acc, tuple) and len(acc) >= 2 else None)
        if not isinstance(addr, IRAddress) or addr.space != MemSpace.SS:
            continue

        if addr.status != AddressStatus.STABLE:
            continue

        if addr.base in {("bp",), ("sp",)}:
            continue

        raise PipelineHardError(
            f"stable SS address is not BP/SP-relative before alias: "
            f"base={addr.base} offset={addr.offset}",
            layer="semantics.stack_frame_recovery",
        )


__all__ = [
    "StackFrameInfo8616",
    "detect_stack_frame_8616",
    "compute_bp_offset",
    "normalize_stack_address_8616",
    "normalize_semantic_accesses_8616",
    "assert_no_unresolved_stable_ss_before_alias_8616",
    "_count_ss_accesses",
    "_count_sp_provisional",
    "_count_sp_stable",
    "_count_bp_stable",
    "_gather_ir_artifacts_from_function_blocks",
    "_detect_sp_proven_delta_from_blocks",
    "_looks_like_frame_evidence",
]
