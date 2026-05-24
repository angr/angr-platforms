from __future__ import annotations

from .patch_dirty import apply_patch as _apply_dirty_patch
from .stack_compat import apply_x86_16_stack_compatibility as _apply_stack_compatibility
from .typehoon_compat import apply_x86_16_typehoon_compatibility as _apply_typehoon_compatibility

__all__ = ["apply_x86_16_compatibility"]


def apply_x86_16_compatibility() -> None:
    _apply_stack_compatibility()
    _apply_typehoon_compatibility()
    _apply_dirty_patch()



