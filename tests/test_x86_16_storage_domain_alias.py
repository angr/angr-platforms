import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

from angr_platforms.X86_16.alias_model import (
    _CopyAliasState,
    _merge_storage_domains,
    _stack_slot_identity_can_join,
    _StackPointerAliasState,
    _StackSlotIdentity,
    _StorageDomainSignature,
    _StorageView,
)


def _make_codegen():
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=SimpleNamespace()),
        cstyle_null_cmp=False,
    )


def test_storage_domain_classifier_distinguishes_variable_domains():
    stack = _decompile._storage_domain_for_variable(_decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000))
    reg = _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 2, name="v14"))
    mem = _decompile._storage_domain_for_variable(_decompile.SimMemoryVariable(0x2000, 2, name="v15"))

    assert stack == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))
    assert stack.stack_slot == _StackSlotIdentity("bp", -4, 2, region=0x1000)
    assert reg == _StorageDomainSignature("register", 2, _StorageView(0, 16))
    assert mem == _StorageDomainSignature("memory", 2, _StorageView(0x2000 * 8, 16))


def test_storage_domain_classifier_preserves_far_pointer_segment_and_offset_identity():
    codegen = _make_codegen()
    expr = _decompile.structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            _decompile.structured_c.CConstant(0x40, _decompile.SimTypeShort(False), codegen=codegen),
            _decompile.structured_c.CConstant(0x17, _decompile.SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )

    facts = _decompile.describe_alias_storage(expr)

    assert facts.domain == _StorageDomainSignature("far_pointer", 32, _StorageView(0, 32))
    assert facts.identity == ("far_pointer", (0x40, 0x17))


def test_storage_domain_classifier_distinguishes_subregister_widths():
    assert _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 1, name="al")).view == _StorageView(0, 8)
    assert _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 1, name="ah")).view == _StorageView(8, 8)
    assert _decompile._storage_domain_for_variable(_decompile.SimRegisterVariable(30, 2, name="ax")).view == _StorageView(0, 16)


def test_storage_domain_classifier_joins_adjacent_views():
    high_view = _StorageDomainSignature("register", 1, _StorageView(8, 8))
    low_view = _StorageDomainSignature("register", 1, _StorageView(0, 8))

    joined = low_view.join(high_view)

    assert joined == _StorageDomainSignature("register", 2, _StorageView(0, 16))
    assert _StorageView(0, 8).can_join(_StorageView(8, 8))


def test_storage_domain_classifier_joins_adjacent_stack_views():
    low_view = _StorageDomainSignature("stack", 1, _StorageView(-32, 8))
    high_view = _StorageDomainSignature("stack", 1, _StorageView(-24, 8))

    assert low_view.can_join(high_view)
    assert low_view.join(high_view) == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))


def test_storage_domain_classifier_tracks_bp_stack_slot_identity():
    low_view = _StorageDomainSignature(
        "stack",
        1,
        _StorageView(-32, 8),
        stack_slot=_StackSlotIdentity("bp", -4, 1, region=0x1000),
    )
    high_view = _StorageDomainSignature(
        "stack",
        1,
        _StorageView(-24, 8),
        stack_slot=_StackSlotIdentity("bp", -3, 1, region=0x1000),
    )

    joined = low_view.join(high_view)

    assert joined is not None
    assert joined.stack_slot == _StackSlotIdentity("bp", -4, 2, region=0x1000)
    assert joined == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))


def test_storage_domain_classifier_canonicalizes_ss_stack_slot_identity():
    stack = _decompile._storage_domain_for_variable(
        _decompile.SimStackVariable(-4, 2, base="ss", name="v1", region=0x1000)
    )

    assert stack.stack_slot == _StackSlotIdentity("bp", -4, 2, region=0x1000)
    assert stack.stack_slot.base == "bp"


def test_storage_domain_classifier_rejects_mismatched_bp_stack_regions():
    low_view = _StorageDomainSignature(
        "stack",
        1,
        _StorageView(-32, 8),
        stack_slot=_StackSlotIdentity("bp", -4, 1, region=0x1000),
    )
    high_view = _StorageDomainSignature(
        "stack",
        1,
        _StorageView(-24, 8),
        stack_slot=_StackSlotIdentity("bp", -3, 1, region=0x2000),
    )

    assert not low_view.can_join(high_view)
    assert low_view.join(high_view) is None


def test_same_stack_slot_identity_requires_exact_bp_slot():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v2", region=0x1000),
        codegen=codegen,
    )
    other_region = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v3", region=0x2000),
        codegen=codegen,
    )

    assert not _decompile._same_stack_slot_identity(low, high)
    assert not _decompile._same_stack_slot_identity(low, other_region)


def test_same_stack_slot_identity_normalizes_ss_backed_slices():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="ss", name="v2", region=0x1000),
        codegen=codegen,
    )

    assert _decompile._same_stack_slot_identity(low, high)


def test_stack_offset_classifier_normalizes_wrapped_16bit_offsets():
    codegen = _make_codegen()
    stack_var = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    expr = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CUnaryOp("Reference", stack_var, codegen=codegen),
        _decompile.structured_c.CConstant(65532, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    matched = _decompile._match_stack_cvar_and_offset(expr)

    assert matched is not None
    matched_var, matched_offset = matched
    assert matched_var is stack_var
    assert matched_offset == -4


def test_stack_slot_identity_normalizes_wrapped_16bit_bp_offsets():
    wrapped = _decompile.SimStackVariable(0xFFFE, 2, base="bp", name="arg_fffe", region=0x1000)
    signed = _decompile.SimStackVariable(-2, 2, base="bp", name="iRow", region=0x1000)

    assert _decompile._stack_slot_identity_for_variable(wrapped) == _decompile._stack_slot_identity_for_variable(signed)


def test_stack_slot_identity_can_join_adjacent_bp_slices():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v2", region=0x1000),
        codegen=codegen,
    )
    other_region = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v3", region=0x2000),
        codegen=codegen,
    )

    assert _stack_slot_identity_can_join(low.variable, high.variable)
    assert not _stack_slot_identity_can_join(low.variable, other_region.variable)


def test_stack_slot_identity_can_join_adjacent_bp_and_ss_slices():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="ss", name="v2", region=0x1000),
        codegen=codegen,
    )

    assert _decompile._stack_slot_identity_can_join(low, high)


def test_decompile_stack_slot_identity_can_join_wrapper_accepts_joinable_bp_slices():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="v1", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v2", region=0x1000),
        codegen=codegen,
    )
    other_region = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="bp", name="v3", region=0x2000),
        codegen=codegen,
    )

    assert _decompile._stack_slot_identity_can_join(low, high)
    assert not _decompile._stack_slot_identity_can_join(low, other_region)


def test_storage_domain_merge_helper_prefers_joinable_domains():
    low = _StorageDomainSignature("register", 1, _StorageView(0, 8))
    high = _StorageDomainSignature("register", 1, _StorageView(8, 8))
    mixed = _StorageDomainSignature("stack", 2, _StorageView(0, 16))

    assert _merge_storage_domains(low, high) == _StorageDomainSignature("register", 2, _StorageView(0, 16))
    assert _merge_storage_domains(low, mixed) == _StorageDomainSignature("mixed")


def test_storage_domain_classifier_marks_mixed_expressions():
    codegen = _make_codegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    reg_var = _decompile.SimRegisterVariable(30, 2, name="v14")
    stack_expr = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    reg_expr = _decompile.structured_c.CVariable(reg_var, codegen=codegen)

    pure_stack = _decompile.structured_c.CBinaryOp(
        "Add",
        stack_expr,
        _decompile.structured_c.CConstant(2, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    mixed = _decompile.structured_c.CBinaryOp("Add", stack_expr, reg_expr, codegen=codegen)

    assert _decompile._storage_domain_for_expr(pure_stack) == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))
    assert _decompile._storage_domain_for_expr(mixed) == _StorageDomainSignature("mixed")


def test_copy_alias_state_stops_mixed_domain_inlining():
    plain = _CopyAliasState(_StorageDomainSignature("register", 2), object())
    mixed = _CopyAliasState(_StorageDomainSignature("mixed"), object(), needs_synthesis=True)

    assert plain.can_inline()
    assert not mixed.can_inline()
    assert str(plain.domain) == "register:2"


def test_copy_alias_state_merge_keeps_joinable_domains_together():
    low = _CopyAliasState(_StorageDomainSignature("register", 1, _StorageView(0, 8)), object())
    high = _CopyAliasState(_StorageDomainSignature("register", 1, _StorageView(8, 8)), object(), needs_synthesis=True)

    merged = low.merge(high)

    assert merged.domain == _StorageDomainSignature("register", 2, _StorageView(0, 16))
    assert merged.needs_synthesis


def test_stack_pointer_alias_state_tracks_base_and_offset():
    codegen = _make_codegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    cvar = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    state = _StackPointerAliasState(cvar, 6)

    shifted = state.shifted(-2)

    assert shifted.base is cvar
    assert shifted.offset == 4
