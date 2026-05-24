from __future__ import annotations

from .calling_convention_compat import apply_x86_16_calling_convention_compatibility
from .compat import apply_x86_16_compatibility
from .decompiler_postprocess_stage import apply_x86_16_decompiler_postprocess
from .decompiler_return_compat import apply_x86_16_decompiler_return_compatibility
from .decompiler_structuring_stage import apply_x86_16_decompiler_structuring

__all__ = ["apply_x86_16_bootstrap"]


def describe_x86_16_bootstrap() -> tuple[str, str]:
    return (
        "apply_x86_16_calling_convention_compatibility",
        "apply_x86_16_compatibility",
        "apply_x86_16_decompiler_return_compatibility",
        "apply_x86_16_decompiler_structuring",
        "apply_x86_16_decompiler_postprocess",
    )


def apply_x86_16_bootstrap() -> None:
    apply_x86_16_calling_convention_compatibility()
    apply_x86_16_compatibility()
    apply_x86_16_decompiler_return_compatibility()
    apply_x86_16_decompiler_structuring()
    apply_x86_16_decompiler_postprocess()



