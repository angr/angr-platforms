"""Substitute `(ss << 4) ± BP ± offset` patterns with named stack variables in C output.

AGENTS rule: rewrite must NOT do semantic recovery.
"""

from __future__ import annotations

import re
from typing import Sequence


def _signed16(value: int) -> int:
    """Convert unsigned 16-bit int to signed."""
    if value >= 0x8000:
        return value - 0x10000
    return value


def substitute_ss_bp_dereferences_with_variables(
    c_text: str,
    bindings: Sequence[object],
) -> str:
    """Replace all `(ss << 4) + BP ± offset` patterns with named variables."""
    if not bindings:
        return c_text

    offset_map: dict[int, str] = {}
    for b in bindings:
        off = getattr(b, "offset", None)
        name = getattr(b, "name", None)
        if isinstance(off, int) and isinstance(name, str):
            offset_map[off] = name

    if not offset_map:
        return c_text

    pattern = re.compile(
        r'\*?\s*'
        r'(?:\(\s*unsigned\s+(?:__)?int\d*\s*\*?\s*\)\s*(?:&?\()?)?'
        r'\(\s*\(\s*ss\s*<<\s*4\s*\)\s*\+\s*BP\s*\)\s*'
        r'([+-])\s*'
        r'(0x[0-9a-fA-F]+|\d+)'
    )

    def replacer(m: re.Match) -> str:
        sign_str = m.group(1).strip()
        offset_str = m.group(2).strip()
        offset_value = int(offset_str, 16 if offset_str.startswith('0x') else 10)
        sign = 1 if sign_str == '+' else -1
        signed_val = _signed16(offset_value * sign)
        if signed_val in offset_map:
            name = offset_map[signed_val]
            full_match = m.group(0)
            is_deref = full_match.lstrip().startswith('*')
            return name if is_deref else f"&{name}"
        return m.group(0)

    result = pattern.sub(replacer, c_text)

    pattern2 = re.compile(
        r'\(\s*\(\s*ss\s*<<\s*4\s*\)\s*\+\s*BP\s*\)\s*'
        r'([+-])\s*'
        r'(0x[0-9a-fA-F]+|\d+)'
    )
    result = pattern2.sub(replacer, result)

    return result


def apply_stack_variable_bindings_to_c_text(
    c_text: str,
    codegen: object,
) -> str:
    """Apply fact-based stack variable bindings to C text."""
    bindings = getattr(codegen, "_inertia_stack_variable_bindings", None)
    if not bindings:
        facts = getattr(codegen, "_inertia_semantic_alias_facts", None)
        if facts:
            # Lazy import to avoid bootstrap dependency
            from .stack_variable_binding import build_stack_variable_bindings_from_alias_facts_8616
            bindings = build_stack_variable_bindings_from_alias_facts_8616(facts)
            codegen._inertia_stack_variable_bindings = bindings
        else:
            return c_text
    if not bindings:
        return c_text
    return substitute_ss_bp_dereferences_with_variables(c_text, bindings)


__all__ = [
    "substitute_ss_bp_dereferences_with_variables",
    "apply_stack_variable_bindings_to_c_text",
]
