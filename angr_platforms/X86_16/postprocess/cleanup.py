from __future__ import annotations

# Layer: Postprocess
# Responsibility: cleanup-stage compatibility exports for postprocess passes.
# Forbidden: alias/widening ownership and primary semantic recovery.

from .. import decompiler_postprocess as _decompiler_postprocess

globals().update(
    {
        name: getattr(_decompiler_postprocess, name)
        for name in dir(_decompiler_postprocess)
        if not name.startswith("__")
    }
)

__all__ = tuple(name for name in dir(_decompiler_postprocess) if not name.startswith("__"))
