from __future__ import annotations

# Layer: IR
# Responsibility: typed value-domain aliases and value IR constructors.
# Forbidden: alias/widening ownership and late rewrite semantics.

from .core import IRValue, MemSpace

__all__ = ["IRValue", "MemSpace", "build_value_ir_8616"]


def build_value_ir_8616(
    *,
    space: MemSpace,
    name: str | None = None,
    offset: int = 0,
    const: int | None = None,
    size: int = 0,
    version: int | None = None,
    expr: tuple[str, ...] | None = None,
) -> IRValue:
    return IRValue(
        space=space,
        name=name,
        offset=offset,
        const=const,
        size=size,
        version=version,
        expr=expr,
    )
