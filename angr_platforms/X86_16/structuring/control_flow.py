from __future__ import annotations

# Layer: Structuring
# Responsibility: control-flow structuring ownership
# Forbidden: CLI formatting and postprocess cleanup ownership

from .. import decompiler_structuring_stage as _decompiler_structuring_stage

globals().update(
    {name: getattr(_decompiler_structuring_stage, name) for name in dir(_decompiler_structuring_stage) if not name.startswith("__")}
)
__all__ = [name for name in dir(_decompiler_structuring_stage) if not name.startswith("__")]
