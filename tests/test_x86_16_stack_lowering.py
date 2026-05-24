from __future__ import annotations

"""Regression tests for stack variable binding and lowering.

AGENTS rule: SS:BP-2 → local_*, SS:BP+4 → arg_*, no stack[x].
"""

import pytest
from types import SimpleNamespace
from angr_platforms.X86_16.alias.alias_model_impl import (
    _StackSlotIdentity,
    _stack_storage_facts_for_segmented_address_8616,
    _stack_slot_identity_for_variable,
    _same_stack_slot_identity,
    _stack_slot_identity_can_join,
    AliasStorageFacts,
    AliasFailure,
    alias_facts_for_ir_address_8616,
)
from angr_platforms.X86_16.ir.core import (
    IRAddress,
    MemSpace,
    AddressStatus,
    SegmentOrigin,
    is_stack_address_8616,
)
from angr.sim_type import SimTypeShort


class TestStackObjectNaming:
    """Stack variable names must follow the convention: local_N for negatives, arg_N for positives."""

    def test_stack_object_name_negative(self):
        from angr_platforms.X86_16.lowering.stack_lowering_impl import _stack_object_name
        name = _stack_object_name(-2)
        assert name.startswith("local_"), f"Expected local_ prefix, got {name}"
        assert "2" in name or "fffe" in name.lower()

    def test_stack_object_name_positive(self):
        from angr_platforms.X86_16.lowering.stack_lowering_impl import _stack_object_name
        name = _stack_object_name(4)
        assert name.startswith("arg_"), f"Expected arg_ prefix, got {name}"
        assert "4" in name

    def test_stack_object_name_zero(self):
        from angr_platforms.X86_16.lowering.stack_lowering_impl import _stack_object_name
        name = _stack_object_name(0)
        assert name.startswith("arg_"), f"Expected arg_ prefix for offset 0, got {name}"
        assert "0" in name

    def test_unknown_positive_stack_slot_uses_local_name_in_codegen_context(self):
        from angr_platforms.X86_16.lowering.stack_lowering_impl import _materialize_stack_cvar_at_offset
        from angr.analyses.decompiler.structured_codegen import c as structured_c
        from angr.sim_variable import SimStackVariable

        class _FakeCodegen:
            def __init__(self):
                self.project = None
                self.cstyle_null_cmp = False
                self._idx = 0
                self.cfunc = SimpleNamespace(
                    addr=0x1000,
                    arg_list=[],
                    variables_in_use={},
                    unified_local_vars={},
                    sort_local_vars=lambda: None,
                )

            def next_idx(self, _name):
                self._idx += 1
                return self._idx

        codegen = _FakeCodegen()
        arg_var = SimStackVariable(4, 2, base="bp", name="arg", region=0x1000)
        arg_type = SimTypeShort(False)
        codegen.cfunc.arg_list = [SimpleNamespace(variable=arg_var)]
        codegen.cfunc.variables_in_use = {arg_var: structured_c.CVariable(arg_var, variable_type=arg_type, codegen=codegen)}

        materialized = _materialize_stack_cvar_at_offset(
            codegen,
            6,
            2,
            resolve_stack_cvar_at_offset=lambda *_args, **_kwargs: None,
            promote_direct_stack_cvariable=lambda *_args, **_kwargs: None,
            stack_type_for_size=lambda size: SimTypeShort(False),
        )

        assert materialized is not None
        materialized_name = getattr(getattr(materialized, "variable", None), "name", None)
        assert materialized_name == "local_6"


class TestStackSlotIdentity:
    """_StackSlotIdentity must track base, offset, width."""

    def test_basic_identity(self):
        slot = _StackSlotIdentity(base="bp", offset=-2, width=2)
        assert slot.base == "bp"
        assert slot.offset == -2
        assert slot.width == 2

    def test_can_join_adjacent(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-2, width=2)
        assert slot_a.can_join(slot_b)

    def test_can_join_adjacent_reverse(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-2, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-4, width=2)
        assert slot_b.can_join(slot_a)

    def test_join_adjacent(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-2, width=2)
        joined = slot_a.join(slot_b)
        assert joined is not None
        assert joined.offset == -4
        assert joined.width == 4

    def test_cannot_join_different_base(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-2, width=2)
        slot_b = _StackSlotIdentity(base="sp", offset=-2, width=2)
        assert not slot_a.can_join(slot_b)

    def test_cannot_join_gapped(self):
        slot_a = _StackSlotIdentity(base="bp", offset=-4, width=2)
        slot_b = _StackSlotIdentity(base="bp", offset=-1, width=2)
        assert not slot_a.can_join(slot_b)

    def test_sp_normalizes_to_bp(self):
        slot = _StackSlotIdentity(base="sp", offset=-2, width=2)
        assert slot.base == "bp"

    def test_ss_normalizes_to_bp(self):
        slot = _StackSlotIdentity(base="ss", offset=-2, width=2)
        assert slot.base == "bp"


class TestStackStorageFactsForSegmentedAddress:
    """SS segment must produce stack storage facts."""

    def test_ss_negative_offset_produces_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", -2, 2)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)
        assert facts.identity[0] == "stack"
        slot = facts.identity[1]
        assert slot.offset == -2
        assert slot.width == 2

    def test_ss_positive_offset_produces_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", 4, 2)
        assert facts is not None
        slot = facts.identity[1]
        assert slot.offset == 4
        assert slot.width == 2

    def test_ds_does_not_produce_stack_facts(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ds", 0, 2)
        assert facts is None

    def test_non_int_offset_is_rejected(self):
        facts = _stack_storage_facts_for_segmented_address_8616("ss", None, 2)
        assert facts is None

    def test_non_ss_segment_rejected(self):
        facts = _stack_storage_facts_for_segmented_address_8616(None, -2, 2)
        assert facts is None


class TestAliasFactsForIRAddress:
    """alias_facts_for_ir_address_8616 must map IRAddress to AliasStorageFacts."""

    def test_ss_stack_address_produces_alias_facts(self):
        addr = IRAddress(
            space=MemSpace.SS,
            base=("bp",),
            offset=0xFFFC,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
            status=AddressStatus.STABLE,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)

    def test_ds_address_produces_memory_facts(self):
        addr = IRAddress(
            space=MemSpace.DS,
            base=("bx",),
            offset=0x100,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)
        assert facts.domain.space == "memory"

    def test_es_address_produces_memory_facts(self):
        addr = IRAddress(
            space=MemSpace.ES,
            base=("di",),
            offset=0x200,
            size=2,
            segment_origin=SegmentOrigin.PROVEN,
        )
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is not None
        assert isinstance(facts, AliasStorageFacts)
        assert facts.domain.space == "memory"

    def test_unknown_space_returns_none(self):
        addr = IRAddress(space=MemSpace.UNKNOWN, offset=0)
        facts = alias_facts_for_ir_address_8616(addr)
        assert facts is None


class TestAliasFailure:
    """AliasFailure signals unresolvable proven addresses."""

    def test_alias_failure_creation(self):
        failure = AliasFailure(
            reason="proven SS space not classifiable as stack slot",
            offset=0xFFFC,
            space="ss",
        )
        assert failure.reason
        assert failure.offset == 0xFFFC
        assert failure.space == "ss"


class TestStackVariableMaterializationDiagnostics:
    """Verify stack variable naming follows the convention."""

    def test_naming_convention_no_bare_stack_index(self):
        """Generated names should never be 'stack[...]'."""
        from angr_platforms.X86_16.lowering.stack_lowering_impl import _stack_object_name
        for offset in (-10, -2, 0, 4, 6, 8):
            name = _stack_object_name(offset)
            assert "stack[" not in name, f"Offset {offset} produced bad name: {name}"
            assert "(ss" not in name, f"Offset {offset} produced bad name: {name}"
