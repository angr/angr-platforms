from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat alias_state import surface during alias package migration.
# Forbidden: semantic ownership; import canonical alias.state only.

from .alias import state as _state

globals().update(
    {
        name: getattr(_state, name)
        for name in dir(_state)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _state,
    "__all__",
    tuple(name for name in dir(_state) if not name.startswith("__")),
)
