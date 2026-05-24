from __future__ import annotations

# Layer: Semantics
# Responsibility: typed flag/condition semantics helpers
# Forbidden: CLI formatting and postprocess cleanup ownership

from .alu_semantics import build_compare_condition_8616
from ..ir.condition_ir import (
    build_condition_ir_8616,
    condition_compare_symbol_8616,
    is_condition_compare_family_8616,
    is_signed_condition_8616,
    is_unsigned_condition_8616,
)

__all__ = [
    "build_compare_condition_8616",
    "build_condition_ir_8616",
    "condition_compare_symbol_8616",
    "is_condition_compare_family_8616",
    "is_signed_condition_8616",
    "is_unsigned_condition_8616",
]
