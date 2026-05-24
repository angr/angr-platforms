from __future__ import annotations

# Layer: IR
# Responsibility: typed address-domain alias exports.
# Forbidden: object/type inference and rewrite-stage recovery.

from ..address_ir import AddressIR8616, build_address_ir_8616, resolved_operand_to_address_ir_8616
from .core import AddressStatus, IRAddress, MemSpace, SegmentOrigin

__all__ = [
    "AddressIR8616",
    "AddressStatus",
    "IRAddress",
    "MemSpace",
    "SegmentOrigin",
    "build_address_ir_8616",
    "resolved_operand_to_address_ir_8616",
]
