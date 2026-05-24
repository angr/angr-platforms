"""Guard that blocks linearized segment expressions from leaking into semantic layers.

AGENTS rule #3: `(seg << 4) + offset` is forbidden as IR.
Linear addresses are allowed ONLY for execution/debugging.

This module provides a hard assertion that must precede any semantic
export path.  When triggered it raises PipelineHardError — never a
silent fallback.
"""

from __future__ import annotations

from .errors import PipelineHardError

# Patterns that MUST NOT appear in any semantic context (IR, alias, type, lowering, structuring, rewrite).
_FORBIDDEN_LINEAR_PATTERNS: tuple[str, ...] = (
    "Shl(reg:ss,const:4)",
    "ss << 4",
    "(ss << 4)",
    "Shl(reg:ds,const:4)",
    "ds << 4",
    "Shl(reg:es,const:4)",
    "es << 4",
)


def _text_contains_forbidden_linear_pattern(text: str) -> str | None:
    """Return the first matching forbidden pattern, or None."""
    for pattern in _FORBIDDEN_LINEAR_PATTERNS:
        if pattern in text:
            return pattern
    return None


def assert_no_linearized_segment_expr_8616(
    expr: object, *, layer: str, function_addr: int | None = None
) -> None:
    """Raise PipelineHardError if *expr* contains a linearized segment term.

    Call this before any semantic log, artifact emission, or postprocess
    validation surface receives an expression that the pipeline will later
    treat as semantic.

    Args:
        expr: Any expression whose text representation is checked.
        layer: Semantic layer name for the error message.
        function_addr: Optional address for diagnostics.
    """
    text = repr(expr)
    pattern = _text_contains_forbidden_linear_pattern(text)
    if pattern is None:
        return
    raise PipelineHardError(
        f"linearized segment expression leaked into {layer}: "
        f"forbidden pattern {pattern!r} in {text[:200]}",
        layer=layer,
        function_addr=function_addr,
    )


__all__ = ["assert_no_linearized_segment_expr_8616"]