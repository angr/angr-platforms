from __future__ import annotations

# Layer: IR
# Responsibility: typed address artifacts bridged from resolved operands.
# Forbidden: object/type guessing and rewrite ownership.

from dataclasses import dataclass

from .addressing_helpers import ResolvedMemoryOperand
from .ir.core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

__all__ = [
    "AddressIR8616",
    "build_address_ir_8616",
    "resolved_operand_to_address_ir_8616",
]


@dataclass(frozen=True, slots=True)
class AddressIR8616:
    space: MemSpace
    base: tuple[str, ...]
    offset: int
    size: int
    status: AddressStatus
    segment_origin: SegmentOrigin

    def to_ir_address(self) -> IRAddress:
        return IRAddress(
            space=self.space,
            base=self.base,
            offset=self.offset,
            size=self.size,
            status=self.status,
            segment_origin=self.segment_origin,
        )


def build_address_ir_8616(
    space: MemSpace,
    base: tuple[str, ...] = (),
    *,
    offset: int = 0,
    size: int = 0,
    status: AddressStatus = AddressStatus.UNKNOWN,
    segment_origin: SegmentOrigin = SegmentOrigin.UNKNOWN,
) -> AddressIR8616:
    return AddressIR8616(
        space=space,
        base=base,
        offset=offset,
        size=size,
        status=status,
        segment_origin=segment_origin,
    )


def resolved_operand_to_address_ir_8616(operand: ResolvedMemoryOperand) -> IRAddress:
    return operand.typed_address()
