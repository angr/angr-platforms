from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: re-export moved postprocess flag cleanup module

from .postprocess import flags_cleanup as _flags_cleanup

globals().update(
    {
        name: getattr(_flags_cleanup, name)
        for name in dir(_flags_cleanup)
        if not name.startswith("__")
    }
)

__all__ = getattr(_flags_cleanup, "__all__", tuple())
