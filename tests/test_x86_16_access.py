from __future__ import annotations

from angr_platforms.X86_16.access import MODE_READ, MODE_WRITE, DataAccess
from angr_platforms.X86_16.addressing_helpers import resolve_memory_operand_8616
from angr_platforms.X86_16.ir.core import AddressStatus, MemSpace, SegmentOrigin
from angr_platforms.X86_16.regs import sgreg_t


class _FakeAccess:
    def __init__(self):
        self._inertia_last_resolved_operand = None
        self._inertia_resolved_operands = []
        self.reads = []
        self.writes = []

    _record_resolved_operand = DataAccess._record_resolved_operand
    _resolve_memory_operand = DataAccess._resolve_memory_operand
    _resolved_segment_operand = DataAccess._resolved_segment_operand

    def convert_ss_vaddr(self, addr):
        return ("ss-linear", addr)

    def v2p(self, seg, addr):
        return ("linear", seg, addr)

    def read_mem8(self, paddr):
        self.reads.append((8, paddr))
        return ("byte", paddr)

    def read_mem16(self, paddr):
        self.reads.append((16, paddr))
        return ("word", paddr)

    def read_mem32(self, paddr):
        self.reads.append((32, paddr))
        return ("dword", paddr)

    def write_mem8(self, paddr, value):
        self.writes.append((8, paddr, value))

    def write_mem16(self, paddr, value):
        self.writes.append((16, paddr, value))

    def write_mem32(self, paddr, value):
        self.writes.append((32, paddr, value))


def test_segment_access_records_typed_operand_before_flattening():
    access = _FakeAccess()

    result = DataAccess.read_mem16_seg(access, sgreg_t.DS, 0x1234)

    assert result == ("word", ("linear", sgreg_t.DS, 0x1234))
    mode, operand = access._inertia_resolved_operands[-1]
    assert mode == MODE_READ
    typed = operand.typed_address()
    assert typed.space is MemSpace.DS
    assert typed.status is AddressStatus.STABLE
    assert typed.segment_origin is SegmentOrigin.PROVEN


def test_ss_access_keeps_stack_space_in_recorded_operand():
    access = _FakeAccess()

    DataAccess.write_mem16_seg(access, sgreg_t.SS, 0x20, 0xABCD)

    mode, operand = access._inertia_resolved_operands[-1]
    assert mode == MODE_WRITE
    assert operand.linear == ("ss-linear", 0x20)
    typed = operand.typed_address()
    assert typed.space is MemSpace.SS
    assert typed.status is AddressStatus.STABLE
    assert typed.segment_origin is SegmentOrigin.PROVEN


def test_resolve_memory_operand_builder_owns_linear_and_typed_policy():
    access = _FakeAccess()

    ds_operand = resolve_memory_operand_8616(access, sgreg_t.DS, 0x100, 16)
    ss_operand = resolve_memory_operand_8616(access, sgreg_t.SS, 0x22, 16)

    assert ds_operand.linear == ("linear", sgreg_t.DS, 0x100)
    assert ds_operand.typed_address().space is MemSpace.DS
    assert ds_operand.typed_address().segment_origin is SegmentOrigin.PROVEN

    assert ss_operand.linear == ("ss-linear", 0x22)
    assert ss_operand.typed_address().space is MemSpace.SS
    assert ss_operand.typed_address().segment_origin is SegmentOrigin.PROVEN
