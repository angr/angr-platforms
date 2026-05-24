from __future__ import annotations

# Layer: Compatibility shim
# Responsibility: preserve flat alias_domains import surface during alias package migration.
# Forbidden: semantic ownership; import canonical alias.domains only.

from .alias import domains as _domains

globals().update(
    {
        name: getattr(_domains, name)
        for name in dir(_domains)
        if not name.startswith("__")
    }
)

__all__ = getattr(
    _domains,
    "__all__",
    tuple(name for name in dir(_domains) if not name.startswith("__")),
)
