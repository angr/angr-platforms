from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat alias_transfer import surface during alias package migration.
# Forbidden: semantic ownership; import canonical alias.transfer only.

from .alias import transfer as _transfer

globals().update(
    {
        name: getattr(_transfer, name)
        for name in dir(_transfer)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _transfer,
    "__all__",
    tuple(name for name in dir(_transfer) if not name.startswith("__")),
)
