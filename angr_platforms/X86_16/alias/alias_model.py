from __future__ import annotations

# Layer: Alias
# Responsibility: canonical storage identity and alias-state ownership
# Forbidden: CLI formatting, loop recovery, postprocess cleanup

from . import alias_model_impl as _alias_model_impl

globals().update(
    {
        name: getattr(_alias_model_impl, name)
        for name in dir(_alias_model_impl)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _alias_model_impl,
    "__all__",
    tuple(name for name in dir(_alias_model_impl) if not name.startswith("__")),
)

