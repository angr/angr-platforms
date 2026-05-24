from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat import surface during alias package migration.
# Forbidden: semantic ownership; import canonical implementation only.

from .alias import alias_model as _alias_model

globals().update(
    {
        name: getattr(_alias_model, name)
        for name in dir(_alias_model)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _alias_model,
    "__all__",
    tuple(name for name in dir(_alias_model) if not name.startswith("__")),
)

