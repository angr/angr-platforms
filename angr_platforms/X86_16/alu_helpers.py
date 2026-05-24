from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: re-export moved semantics module

from .semantics import alu_semantics as _alu_semantics

globals().update(
    {
        name: getattr(_alu_semantics, name)
        for name in dir(_alu_semantics)
        if not name.startswith("__")
    }
)

__all__ = getattr(_alu_semantics, "__all__", tuple())
