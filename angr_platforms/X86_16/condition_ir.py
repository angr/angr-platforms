from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: re-export moved IR condition module

from .ir import condition_ir as _condition_ir

globals().update(
    {
        name: getattr(_condition_ir, name)
        for name in dir(_condition_ir)
        if not name.startswith("__")
    }
)

__all__ = getattr(_condition_ir, "__all__", tuple())
