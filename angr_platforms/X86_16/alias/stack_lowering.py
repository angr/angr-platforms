from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve legacy alias.stack_lowering imports during migration.
# Forbidden: semantic ownership; import lowering canonical path only.

from ..lowering.stack_lowering import (
    _canonicalize_stack_cvar_expr,
    _canonicalize_stack_cvars,
    _materialize_stack_cvar_at_offset,
    _resolve_stack_cvar_at_offset,
    _resolve_stack_cvar_from_addr_expr,
    run_stack_lowering_pass_8616,
)

__all__ = (
    "_canonicalize_stack_cvar_expr",
    "_canonicalize_stack_cvars",
    "_materialize_stack_cvar_at_offset",
    "_resolve_stack_cvar_at_offset",
    "_resolve_stack_cvar_from_addr_expr",
    "run_stack_lowering_pass_8616",
)
