from __future__ import annotations

__all__ = ["include_x86_16_tail_validation_stack_write"]


def include_x86_16_tail_validation_stack_write(
    location: str,
    *,
    mode: str,
    observed_locations: set[str],
) -> bool:
    if mode == "coarse":
        return True
    if not location.startswith("stack:"):
        return False
    # [bp+0] is not a stable user-visible stack slot in the 16-bit frame model.
    # Postprocess can transiently synthesize carrier writes there while recovering
    # arguments; treating it as a live-out observable produces false deltas.
    if location == "stack:+0x0":
        return False
    if location.startswith("stack:-"):
        return False
    return location in observed_locations
