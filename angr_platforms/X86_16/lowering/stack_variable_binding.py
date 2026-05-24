from __future__ import annotations

# Layer: Lowering (early type manifestation)
# Responsibility: bind stable SS/BP stack accesses to named local variable identities before late rewrite.
# Forbidden: text-pattern semantics, postprocess cleanup ownership, widening from shape alone.

from ..ir.core import IRAddress, IRValue, MemSpace, AddressStatus, SegmentOrigin

__all__ = [
    "StackVariableBinding",
    "build_stack_variable_bindings_8616",
]


class StackVariableBinding:
    """A stable binding from a stack access to a local variable identity.

    This represents: ``[ss:bp-N]`` → local variable ``v_N``.

    Bindings are only created when the alias model has proven stability:
    - The segment is proven STABLE SS
    - The offset is a constant BP-offset
    - No cross-segment ambiguity exists
    """

    __slots__ = ("bp_offset", "size", "var_name", "is_stable")

    def __init__(self, bp_offset: int, size: int, *, var_name: str | None = None, is_stable: bool = True) -> None:
        self.bp_offset = bp_offset
        self.size = size
        self.var_name = var_name or f"var_{abs(bp_offset):x}"
        self.is_stable = is_stable

    def __repr__(self) -> str:
        return f"StackVariableBinding(bp_offset={self.bp_offset}, size={self.size}, var_name={self.var_name!r}, stable={self.is_stable})"

    def to_dict(self) -> dict[str, object]:
        return {
            "bp_offset": self.bp_offset,
            "size": self.size,
            "var_name": self.var_name,
            "is_stable": self.is_stable,
        }


def build_stack_variable_bindings_8616(
    addresses: list[tuple[int, int]],  # (offset, size) pairs
    *,
    preferred_names: dict[int, str] | None = None,
) -> list[StackVariableBinding]:
    """Build stable local variable bindings from a sorted list of stack offsets.

    Args:
        addresses: Sorted list of (bp_offset, size) pairs (negative offsets for locals)
        preferred_names: Optional mapping of offset → preferred variable name

    Returns:
        Sorted list of StackVariableBinding objects

    Adjacent offsets with matching segment origin are NOT blindly folded;
    binding stability requires alias proof which is the caller's responsibility.
    """
    bindings: list[StackVariableBinding] = []
    for offset, size in addresses:
        var_name = None
        if preferred_names is not None:
            var_name = preferred_names.get(offset)
        binding = StackVariableBinding(offset, size, var_name=var_name)
        bindings.append(binding)
    return sorted(bindings, key=lambda b: b.bp_offset)


def stable_ss_address_to_ir_value_8616(offset: int, size: int) -> IRValue:
    """Convert a stable SS/Bp offset into an IRValue.

    This preserves segment identity and stability status.
    """
    return IRValue(
        space=MemSpace.SS,
        name="bp",
        offset=offset,
        size=size,
    )


def stable_ss_offset_to_ir_address_8616(offset: int, size: int) -> IRAddress:
    """Convert a stable SS/Bp offset into an IRAddress with proven stability."""
    return IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=offset,
        size=size,
        status=AddressStatus.STABLE,
        segment_origin=SegmentOrigin.PROVEN,
    )