from __future__ import annotations

"""Regression tests for segmented address IR integrity.

AGENTS rule: SS ≠ DS, DS ≠ ES are distinct memory spaces.
No flattened (ss << 4) in semantic IR.
"""

import pytest
from angr_platforms.X86_16.ir.core import (
    IRAddress,
    MemSpace,
    AddressStatus,
    SegmentOrigin,
    is_stack_address_8616,
)


class TestMemSpaceIdentity:
    """SS, DS, ES must be distinct spaces — never collapsed."""

    def test_ss_distinct_from_ds(self):
        assert MemSpace.SS != MemSpace.DS, "SS must not equal DS"

    def test_ss_distinct_from_es(self):
        assert MemSpace.SS != MemSpace.ES, "SS must not equal ES"

    def test_ds_distinct_from_es(self):
        assert MemSpace.DS != MemSpace.ES, "DS must not equal ES"

    def test_all_memory_spaces_distinct(self):
        mem_spaces = {MemSpace.SS, MemSpace.DS, MemSpace.ES}
        assert len(mem_spaces) == 3, "All memory segments must be distinct"


class TestIRAddressConstruction:
    """IRAddress must carry segmented space, not linear."""

    def test_ss_bp_offset_produces_ir_address(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("ss",),
            offset=0xFFFC,  # BP-4
            size=2,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
            expr=("bp", "-", "4"),
        )
        assert addr.space == MemSpace.SS
        assert addr.offset == 0xFFFC
        assert addr.segment_origin == SegmentOrigin.PROVEN

    def test_no_linear_field_in_ir_address(self):
        """IRAddress must NOT contain any linear/execution address field."""
        addr = IRAddress(space=MemSpace.DS, offset=0x100)
        assert not hasattr(addr, "linear")
        assert not hasattr(addr, "exec_linear")
        assert "linear" not in addr.to_dict()

    def test_expr_preserved_for_symbolic_offset(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=0,
            size=2,
            expr=("bp", "+", "-4"),
        )
        assert addr.expr == ("bp", "+", "-4")


class TestIsStackAddress8616:
    """Proven SS:BP must be detected as stack address."""

    def test_proven_ss_bp_is_stack(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=0xFFFC,
            status=AddressStatus.STABLE,
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert is_stack_address_8616(addr), "Proven SS:BP must be stack"

    def test_defaulted_ss_with_bp_base_is_stack(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=0xFFFE,
            segment_origin=SegmentOrigin.DEFAULTED,
        )
        assert is_stack_address_8616(addr), "Defaulted SS with BP base is stack"

    def test_ss_with_ss_base_is_stack(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("ss",),
            offset=0,
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert is_stack_address_8616(addr), "SS base in SS space is stack"

    def test_expr_with_bp_is_stack(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=(),
            offset=0,
            expr=("bp", "+", "8"),
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert is_stack_address_8616(addr), "BP in expr makes it stack"

    def test_expr_with_sp_is_stack(self):
        addr = IRAddress(
            space=MemSpace.SS,
            expr=("sp", "-", "2"),
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert is_stack_address_8616(addr), "SP in expr makes it stack"

    def test_ds_not_stack(self):
        addr = IRAddress(
            space=MemSpace.DS,
            base=("bx",),
            offset=0x100,
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert not is_stack_address_8616(addr), "DS should not be stack"

    def test_es_not_stack(self):
        addr = IRAddress(
            space=MemSpace.ES,
            base=("di",),
            offset=0,
            segment_origin=SegmentOrigin.PROVEN,
        )
        assert not is_stack_address_8616(addr), "ES should not be stack"

    def test_unknown_space_not_stack(self):
        addr = IRAddress(space=MemSpace.UNKNOWN, offset=0)
        assert not is_stack_address_8616(addr), "UNKNOWN should not be stack"

    def test_ss_without_bp_not_stack(self):
        """SS space without BP/SP hint should not be classified as stack."""
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bx",),  # BX is not BP/SP
            offset=0,
            segment_origin=SegmentOrigin.UNKNOWN,
        )
        assert not is_stack_address_8616(addr)


class TestResolvedMemoryOperandIrAddress:
    """verify ResolvedMemoryOperand.ir_address() produces proper IRAddress."""

    def test_ir_address_reads_segment(self):
        from angr_platforms.X86_16.addressing_helpers import ResolvedMemoryOperand
        from angr_platforms.X86_16.regs import sgreg_t

        operand = ResolvedMemoryOperand(
            segment=sgreg_t.DS,
            offset=0x200,
            exec_linear=0x1200,
            width_bits=16,
            address_bits=16,
        )
        ir_addr = operand.ir_address()
        assert ir_addr.space == MemSpace.DS
        assert ir_addr.offset == 0x200
        assert ir_addr.size == 2

    def test_ss_operand_produces_ss_ir_address(self):
        from angr_platforms.X86_16.addressing_helpers import ResolvedMemoryOperand
        from angr_platforms.X86_16.regs import sgreg_t

        operand = ResolvedMemoryOperand(
            segment=sgreg_t.SS,
            offset=0xFFFC,
            exec_linear=0x0FFFC,
            width_bits=16,
            address_bits=16,
        )
        ir_addr = operand.ir_address()
        assert ir_addr.space == MemSpace.SS
        assert ir_addr.segment_origin == SegmentOrigin.PROVEN

    def test_linear_property_still_accessible_backward_compat(self):
        from angr_platforms.X86_16.addressing_helpers import ResolvedMemoryOperand
        from angr_platforms.X86_16.regs import sgreg_t

        operand = ResolvedMemoryOperand(
            segment=sgreg_t.DS,
            offset=0x100,
            exec_linear=0x1000,
            width_bits=8,
            address_bits=16,
        )
        # linear property must still work for backward compat
        assert operand.linear == operand.exec_linear
        assert operand.linear == 0x1000