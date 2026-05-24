from __future__ import annotations

# Layer: Semantics
# Responsibility: expression-shape interpretation used by semantic query layers.
# Forbidden: storage identity ownership, widening decisions, CLI formatting.

from angr.analyses.decompiler.structured_codegen import c as structured_c


def _unwrap_c_casts(expr):
    while isinstance(expr, structured_c.CTypeCast):
        expr = expr.expr
    return expr


def _constant_int_value(expr) -> int | None:
    expr = _unwrap_c_casts(expr)
    if isinstance(expr, structured_c.CConstant) and isinstance(expr.value, int):
        return expr.value
    return None


def _mk_fp_components(expr) -> tuple[int, int] | None:
    expr = _unwrap_c_casts(expr)
    if not isinstance(expr, structured_c.CFunctionCall) or getattr(expr, "callee_target", None) != "MK_FP":
        return None
    args = list(getattr(expr, "args", ()) or ())
    if len(args) != 2:
        return None
    seg = _constant_int_value(args[0])
    off = _constant_int_value(args[1])
    if seg is None or off is None:
        return None
    return seg, off


__all__ = ["_unwrap_c_casts", "_constant_int_value", "_mk_fp_components"]
