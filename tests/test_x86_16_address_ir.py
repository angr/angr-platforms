from __future__ import annotations

from angr_platforms.X86_16.address_ir import build_address_ir_8616, resolved_operand_to_address_ir_8616
from angr_platforms.X86_16.addressing_helpers import ResolvedMemoryOperand
from angr_platforms.X86_16.ir.core import AddressStatus, MemSpace, SegmentOrigin
from angr_platforms.X86_16.regs import sgreg_t


def test_build_address_ir_keeps_explicit_segment_spaces_distinct():
    ss = build_address_ir_8616(MemSpace.SS, ("bp",), offset=-2, size=2).to_ir_address()
    ds = build_address_ir_8616(MemSpace.DS, ("bx",), offset=8, size=2).to_ir_address()
    es = build_address_ir_8616(MemSpace.ES, ("di",), offset=4, size=1).to_ir_address()

    assert ss.space is MemSpace.SS
    assert ds.space is MemSpace.DS
    assert es.space is MemSpace.ES


def test_resolved_operand_to_address_ir_marks_explicit_segments_proven():
    ss = resolved_operand_to_address_ir_8616(ResolvedMemoryOperand(sgreg_t.SS, -4, 0x1FFC, 16, 16))
    ds = resolved_operand_to_address_ir_8616(ResolvedMemoryOperand(sgreg_t.DS, 8, 0x1008, 16, 16))
    es = resolved_operand_to_address_ir_8616(ResolvedMemoryOperand(sgreg_t.ES, 2, 0x2002, 8, 16))

    assert ss.status is AddressStatus.STABLE
    assert ds.status is AddressStatus.STABLE
    assert es.status is AddressStatus.STABLE
    assert ss.segment_origin is SegmentOrigin.PROVEN
    assert ds.segment_origin is SegmentOrigin.PROVEN
    assert es.segment_origin is SegmentOrigin.PROVEN
