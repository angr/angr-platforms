from __future__ import annotations

# Layer: Postprocess
# Responsibility: final simplification cleanup only
# Forbidden: alias/widening/type ownership

from .. import decompiler_postprocess_simplify as _decompiler_postprocess_simplify

globals().update(
    {
        name: getattr(_decompiler_postprocess_simplify, name)
        for name in dir(_decompiler_postprocess_simplify)
        if not name.startswith("__")
    }
)
__all__ = [name for name in dir(_decompiler_postprocess_simplify) if not name.startswith("__")]
