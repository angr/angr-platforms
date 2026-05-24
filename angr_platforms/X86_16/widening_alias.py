from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat widening_alias import surface during widening package migration.
# Forbidden: semantic ownership; import canonical widening.register_widening only.

from .widening import register_widening as _register_widening

globals().update(
    {
        name: getattr(_register_widening, name)
        for name in dir(_register_widening)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _register_widening,
    "__all__",
    tuple(name for name in dir(_register_widening) if not name.startswith("__")),
)
