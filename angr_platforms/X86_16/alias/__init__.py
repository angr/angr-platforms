# Layer: Alias
# Responsibility: storage identity and stack-slot identity
# Forbidden: CLI formatting, loop recovery, postprocess cleanup

from importlib import import_module

_EXPORT_MODULES = (
    "alias_model",
    "domains",
    "state",
    "transfer",
)

__all__ = tuple(_EXPORT_MODULES)


def __getattr__(name: str):
    if name in _EXPORT_MODULES:
        return import_module(f"{__name__}.{name}")
    raise AttributeError(name)
