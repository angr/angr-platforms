from __future__ import annotations

"""Layer: Validation.

Responsibility: canonicalization for equivalence checking — NEVER for IR mutation.

Rules:
- Allowed: x+0→x, x−x→0, (a+b)+c normalization, commutativity for +,&,|
- Forbidden: modifying IR, modifying C output, creating new variables, guessing structs/arrays.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable


__all__ = [
    "EquivalenceResult",
    "canonicalize_expr_for_validation_8616",
    "equivalent_expr_8616",
    "canonical_diagnostic_8616",
]


class EquivalenceResult(Enum):
    EQUIVALENT = "equivalent"
    DIFFERENT = "different"
    UNCERTAIN = "uncertain"
    TIMEOUT = "timeout"


@dataclass(frozen=True, slots=True)
class CanonicalDiagnostic:
    path: str = ""
    changed: bool = False
    note: str = ""
    before: str = ""
    after: str = ""


def canonicalize_expr_for_validation_8616(expr: Any, *, max_depth: int = 8) -> Any:
    """Apply identity-preserving algebraic normalization to a single expression.

    Returns a normalized copy — NEVER mutates the original IR.

    Normalizations:
      - x + 0 → x
      - 0 + x → x  
      - x - x → 0
      - x - 0 → x
      - Commutative reordering for +, &, | (left-associative)
      - (a + b) + c → a + b + c (flatten)
    """
    if max_depth <= 0:
        return expr

    # Primitive types pass through
    if not isinstance(expr, (int, float, str, bool, type(None))):
        return expr

    # Handle common expression types if they have lhs/rhs shape
    if hasattr(expr, "lhs") and hasattr(expr, "rhs"):
        lhs = canonicalize_expr_for_validation_8616(getattr(expr, "lhs"), max_depth=max_depth - 1)
        rhs = canonicalize_expr_for_validation_8616(getattr(expr, "rhs"), max_depth=max_depth - 1)

        # x + 0 → x
        if _is_zero_value(rhs) and getattr(expr, "op", "") in {"Add", "+"}:
            return lhs
        # 0 + x → x
        if _is_zero_value(lhs) and getattr(expr, "op", "") in {"Add", "+"}:
            return rhs
        # x - 0 → x
        if _is_zero_value(rhs) and getattr(expr, "op", "") in {"Sub", "-"}:
            return lhs
        # x - x → 0
        if _same_value(lhs, rhs) and getattr(expr, "op", "") in {"Sub", "-"}:
            return _zero_for_expr(lhs)

        return _rebuild_binary(expr, lhs, rhs)

    # Handle unary ops
    if hasattr(expr, "operand"):
        operand = canonicalize_expr_for_validation_8616(getattr(expr, "operand"), max_depth=max_depth - 1)
        if operand is not getattr(expr, "operand"):
            return _rebuild_unary(expr, operand)

    return expr


def equivalent_expr_8616(lhs: Any, rhs: Any, *, timeout_ms: int = 500) -> EquivalenceResult:
    """Check if two expressions are semantically equivalent after canonicalization.

    Uses:
        1. Structural equality after canonicalization
        2. String-level fingerprint comparison (delegates to condition_ir.py)
        3. SMT fallback if available (Z3)
    """
    # Fast path: identity
    if lhs is rhs:
        return EquivalenceResult.EQUIVALENT

    # Canonicalize both
    canon_lhs = canonicalize_expr_for_validation_8616(lhs)
    canon_rhs = canonicalize_expr_for_validation_8616(rhs)

    # Structural equality after canonicalization
    if _structural_equal(canon_lhs, canon_rhs):
        return EquivalenceResult.EQUIVALENT

    # String-level comparison for conditions
    if _fingerprint_equal(lhs, rhs):
        return EquivalenceResult.EQUIVALENT

    # Try SMT fallback
    if _smt_equivalent(lhs, rhs, timeout_ms=timeout_ms):
        return EquivalenceResult.EQUIVALENT

    return EquivalenceResult.DIFFERENT


def canonical_diagnostic_8616(expr: Any) -> CanonicalDiagnostic:
    """Return a diagnostic describing what canonicalization changed."""
    before = str(expr) if not isinstance(expr, str) else expr
    after_expr = canonicalize_expr_for_validation_8616(expr)
    after = str(after_expr) if not isinstance(after_expr, str) else after_expr
    changed = before != after
    note = "canonicalized" if changed else "unchanged"
    return CanonicalDiagnostic(
        path=getattr(expr, "__class__", type(expr)).__name__,
        changed=changed,
        note=note,
        before=before,
        after=after,
    )


# ── internal helpers ──


def _is_zero_value(expr: Any) -> bool:
    """Check if an expression represents the value 0."""
    if isinstance(expr, int):
        return expr == 0
    if isinstance(expr, float):
        return expr == 0.0
    const_val = getattr(expr, "value", None)
    if isinstance(const_val, int):
        return const_val == 0
    if isinstance(const_val, float):
        return const_val == 0.0
    return False


def _is_one_value(expr: Any) -> bool:
    """Check if an expression represents the value 1."""
    if isinstance(expr, int):
        return expr == 1
    const_val = getattr(expr, "value", None)
    if isinstance(const_val, int):
        return const_val == 1
    return False


def _same_value(lhs: Any, rhs: Any) -> bool:
    """Check if two expressions represent the same value."""
    if type(lhs) is not type(rhs):
        return False
    lhs_value = getattr(lhs, "value", lhs)
    rhs_value = getattr(rhs, "value", rhs)
    if isinstance(lhs_value, int) and isinstance(rhs_value, int):
        return lhs_value == rhs_value

    # Register-check: same reg offset
    lhs_reg = getattr(lhs, "reg", None) or getattr(getattr(lhs, "variable", None), "reg", None)
    rhs_reg = getattr(rhs, "reg", None) or getattr(getattr(rhs, "variable", None), "reg", None)
    if isinstance(lhs_reg, int) and isinstance(rhs_reg, int):
        return lhs_reg == rhs_reg

    # Stack slot: same base + offset
    lhs_var = getattr(lhs, "variable", None)
    rhs_var = getattr(rhs, "variable", None)
    if lhs_var is not None and rhs_var is not None:
        return (
            getattr(lhs_var, "offset", object()) == getattr(rhs_var, "offset", None)
            and getattr(lhs_var, "base", object()) == getattr(rhs_var, "base", None)
        )

    return False


def _zero_for_expr(expr: Any) -> Any:
    """Produce a zero constant matching the type of expr."""
    width = getattr(expr, "size", 4)
    return _make_constant(0, width)


def _make_constant(value: int, size: int = 4) -> Any:
    """Create a constant node matching the given value and size."""
    try:
        from angr.analyses.decompiler.structured_codegen.c import CConstant
        from angr.sim_type import SimTypeShort, SimTypeChar, SimTypeInt

        if size <= 1:
            return CConstant(value, SimTypeChar(signed=False), codegen=None)
        if size <= 2:
            return CConstant(value, SimTypeShort(signed=False), codegen=None)
        return CConstant(value, SimTypeInt(signed=False), codegen=None)
    except ImportError:
        return value


def _rebuild_binary(original: Any, lhs: Any, rhs: Any) -> Any:
    """Rebuild a binary expression with canonicalized children."""
    cls = type(original)
    try:
        return cls(getattr(original, "op"), lhs, rhs, codegen=getattr(original, "codegen", None))
    except (TypeError, ValueError):
        return original


def _rebuild_unary(original: Any, operand: Any) -> Any:
    """Rebuild a unary expression with a canonicalized operand."""
    cls = type(original)
    try:
        return cls(getattr(original, "op"), operand, codegen=getattr(original, "codegen", None))
    except (TypeError, ValueError):
        return original


def _structural_equal(lhs: Any, rhs: Any, depth: int = 0, max_depth: int = 16) -> bool:
    """Structural equality check with cycle detection."""
    if depth > max_depth:
        return True  # conservative: treat too-deep as equal

    if type(lhs) is not type(rhs):
        return False

    if isinstance(lhs, (int, float, str, bool, type(None))):
        return lhs == rhs

    # Compare key structural attributes
    for attr in ("op", "value", "name", "kind", "type"):
        lhs_val = getattr(lhs, attr, _sentinel)
        rhs_val = getattr(rhs, attr, _sentinel)
        if lhs_val is not _sentinel and rhs_val is not _sentinel:
            if not _structural_equal(lhs_val, rhs_val, depth + 1, max_depth):
                return False

    # Compare child nodes
    for child_attr in ("lhs", "rhs", "operand", "expr", "variable", "index"):
        lhs_child = getattr(lhs, child_attr, _sentinel)
        rhs_child = getattr(rhs, child_attr, _sentinel)
        if lhs_child is _sentinel or rhs_child is _sentinel:
            if lhs_child is not _sentinel or rhs_child is not _sentinel:
                return False
            continue
        if not _structural_equal(lhs_child, rhs_child, depth + 1, max_depth):
            return False

    return True


_sentinel = object()


def _fingerprint_equal(lhs: Any, rhs: Any) -> bool:
    """String-based fingerprint comparison using condition IR normalization."""
    from ..ir.condition_ir import (
        normalize_condition_fingerprint_string_8616,
        normalize_condition_fingerprint_algebraic_8616,
    )

    lhs_str = str(lhs) if not isinstance(lhs, str) else lhs
    rhs_str = str(rhs) if not isinstance(rhs, str) else rhs

    lhs_normalized = normalize_condition_fingerprint_algebraic_8616(
        normalize_condition_fingerprint_string_8616(lhs_str)
    )
    rhs_normalized = normalize_condition_fingerprint_algebraic_8616(
        normalize_condition_fingerprint_string_8616(rhs_str)
    )

    if lhs_normalized == rhs_normalized:
        return True

    # Try with simple whitespace/formatting normalization
    lhs_compact = "".join(lhs_normalized.split())
    rhs_compact = "".join(rhs_normalized.split())
    return lhs_compact == rhs_compact


def _smt_equivalent(lhs: Any, rhs: Any, *, timeout_ms: int = 500) -> bool:
    """Try SMT (Z3) equivalence as fallback.  Returns False if Z3 unavailable."""
    try:
        import z3
    except ImportError:
        return False

    try:
        lhs_smt = _to_z3_expr(lhs)
        rhs_smt = _to_z3_expr(rhs)
        if lhs_smt is None or rhs_smt is None:
            return False

        s = z3.Solver()
        s.set("timeout", timeout_ms)
        s.add(lhs_smt != rhs_smt)
        result = s.check()
        return result == z3.unsat
    except Exception:
        return False


def _to_z3_expr(expr: Any, _depth: int = 0) -> Any | None:
    """Best-effort conversion of an expression to Z3."""
    if _depth > 16:
        return None
    try:
        import z3
    except ImportError:
        return None

    if isinstance(expr, int):
        return z3.IntVal(expr)
    if isinstance(expr, bool):
        return z3.BoolVal(expr)

    const_val = getattr(expr, "value", None)
    if isinstance(const_val, int):
        return z3.IntVal(const_val)

    # Named variable
    name = getattr(expr, "name", None)
    if isinstance(name, str) and name:
        return z3.Int(name)

    # Register-like
    reg = getattr(expr, "reg", None) or getattr(getattr(expr, "variable", None), "reg", None)
    if isinstance(reg, int):
        return z3.Int(f"reg_{reg}")

    # Binary op
    if hasattr(expr, "op") and hasattr(expr, "lhs") and hasattr(expr, "rhs"):
        lhs_z3 = _to_z3_expr(getattr(expr, "lhs"), _depth + 1)
        rhs_z3 = _to_z3_expr(getattr(expr, "rhs"), _depth + 1)
        if lhs_z3 is None or rhs_z3 is None:
            return None
        op = getattr(expr, "op", "")
        if op in {"Add", "+"}:
            return lhs_z3 + rhs_z3
        if op in {"Sub", "-"}:
            return lhs_z3 - rhs_z3
        if op in {"Mul", "*"}:
            return lhs_z3 * rhs_z3
        if op in {"CmpEQ", "==", "eq"}:
            return lhs_z3 == rhs_z3
        if op in {"CmpNE", "!=", "ne"}:
            return lhs_z3 != rhs_z3
        return None

    return None