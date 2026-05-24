from __future__ import annotations

from dataclasses import dataclass

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable

from ..decompiler_postprocess_utils import _replace_c_children_8616


@dataclass(frozen=True, slots=True)
class SegmentedMemoryExpr:
    space: str
    segment_expr: object
    offset_expr: object
    width_bits: int
    access: str


def _strip_casts_8616(node):
    while isinstance(node, structured_c.CTypeCast):
        node = node.expr
    return node


def _constant_value_8616(node) -> int | None:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CConstant) and isinstance(node.value, int):
        return node.value
    return None


def _extract_segment_scale_8616(node, project) -> tuple[str | None, object | None]:
    node = _strip_casts_8616(node)
    if not isinstance(node, structured_c.CBinaryOp):
        return None, None
    expected_scale = 16 if node.op == "Mul" else 4 if node.op == "Shl" else None
    if expected_scale is None:
        return None, None
    for maybe_seg, maybe_scale in ((node.lhs, node.rhs), (node.rhs, node.lhs)):
        if _constant_value_8616(maybe_scale) != expected_scale:
            continue
        maybe_seg = _strip_casts_8616(maybe_seg)
        if not isinstance(maybe_seg, structured_c.CVariable):
            continue
        variable = getattr(maybe_seg, "variable", None)
        if not isinstance(variable, SimRegisterVariable):
            continue
        seg_name = getattr(project.arch, "register_names", {}).get(variable.reg)
        if seg_name is not None:
            return seg_name, maybe_seg
    return None, None


def _flatten_signed_terms_8616(node, sign: int = 1) -> tuple[tuple[int, object], ...]:
    node = _strip_casts_8616(node)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Add":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, sign)
    if isinstance(node, structured_c.CBinaryOp) and node.op == "Sub":
        return _flatten_signed_terms_8616(node.lhs, sign) + _flatten_signed_terms_8616(node.rhs, -sign)
    return ((sign, node),)


def _build_offset_expr_8616(terms: tuple[tuple[int, object], ...], codegen):
    if not terms:
        return structured_c.CConstant(0, SimTypeShort(False), codegen=codegen)

    expr = None
    for sign, term in terms:
        term = _strip_casts_8616(term)
        if expr is None:
            if sign == 1:
                expr = term
            else:
                expr = structured_c.CBinaryOp(
                    "Sub",
                    structured_c.CConstant(0, SimTypeShort(False), codegen=codegen),
                    term,
                    codegen=codegen,
                )
            continue
        expr = structured_c.CBinaryOp("Add" if sign == 1 else "Sub", expr, term, codegen=codegen)
    return expr


def _match_segmented_memory_expr_8616(node, *, project, access: str) -> SegmentedMemoryExpr | None:
    if access == "read" or access == "write":
        node = _strip_casts_8616(node)
        if not isinstance(node, structured_c.CUnaryOp) or node.op != "Dereference":
            return None
        base_expr = node.operand
        width_bits = getattr(getattr(node, "type", None), "size", None) or 16
        codegen = getattr(node, "codegen", None)
    else:
        base_expr = node
        width_bits = 0
        codegen = getattr(node, "codegen", None)

    segment_name = None
    segment_expr = None
    offset_terms: list[tuple[int, object]] = []
    for sign, term in _flatten_signed_terms_8616(base_expr):
        local_name, local_expr = _extract_segment_scale_8616(term, project)
        if local_name is not None:
            if sign != 1 or segment_name is not None:
                return None
            segment_name = local_name.upper()
            segment_expr = local_expr
            continue
        offset_terms.append((sign, term))

    if segment_name not in {"DS", "ES", "SS"} or segment_expr is None:
        return None
    return SegmentedMemoryExpr(
        space=segment_name,
        segment_expr=segment_expr,
        offset_expr=_build_offset_expr_8616(tuple(offset_terms), codegen),
        width_bits=int(width_bits),
        access=access,
    )


def _seg_macro_for_width_bits_8616(width_bits: int) -> str | None:
    if width_bits <= 8:
        return "SEG_U8"
    if width_bits <= 16:
        return "SEG_U16"
    if width_bits <= 32:
        return "SEG_U32"
    return None


def lower_runtime_segment_access_8616(expr, *, target: str):
    project = getattr(getattr(expr, "codegen", None), "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="read")
    if matched is None:
        return None
    if matched.space == "SS":
        return None
    macro = _seg_macro_for_width_bits_8616(matched.width_bits)
    if macro is None:
        return None
    codegen = getattr(expr, "codegen", None)
    return structured_c.CFunctionCall(
        macro,
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": macro},
    )


def lower_runtime_segment_address_8616(expr, *, target: str):
    project = getattr(getattr(expr, "codegen", None), "project", None)
    if project is None:
        return None
    matched = _match_segmented_memory_expr_8616(expr, project=project, access="address")
    if matched is None:
        return None
    if matched.space not in {"DS", "ES"}:
        return None
    codegen = getattr(expr, "codegen", None)
    return structured_c.CFunctionCall(
        "MK_FP",
        None,
        [matched.segment_expr, matched.offset_expr],
        codegen=codegen,
        tags={"inertia_x86_16_runtime_segment_helper": "MK_FP"},
    )


def apply_runtime_segment_lowering_8616(codegen, *, target: str = "portable-flat") -> bool:
    root = getattr(getattr(codegen, "cfunc", None), "statements", None)
    project = getattr(codegen, "project", None)
    if root is None or project is None:
        return False

    changed = False

    def transform(node):
        nonlocal changed
        lowered_access = lower_runtime_segment_access_8616(node, target=target)
        if lowered_access is not None:
            changed = True
            return lowered_access
        lowered_addr = lower_runtime_segment_address_8616(node, target=target)
        if lowered_addr is not None:
            changed = True
            return lowered_addr
        return node

    new_root = transform(root)
    if new_root is not root:
        codegen.cfunc.statements = new_root
        if hasattr(codegen.cfunc, "body"):
            codegen.cfunc.body = new_root
        changed = True
    if _replace_c_children_8616(codegen.cfunc.statements, transform):
        changed = True
    return changed


__all__ = [
    "SegmentedMemoryExpr",
    "apply_runtime_segment_lowering_8616",
    "lower_runtime_segment_access_8616",
    "lower_runtime_segment_address_8616",
]
