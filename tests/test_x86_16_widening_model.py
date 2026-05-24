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

from angr_platforms.X86_16.alias_model import _StackSlotIdentity, _StorageDomainSignature, _StorageView
from angr_platforms.X86_16.widening_model import (
    WideningCandidate,
    analyze_adjacent_storage_slices,
    can_join_adjacent_storage_slices,
    merge_storage_slice_domains,
)


class _DummyCodegen:
    def __init__(self):
        self._idx = 0
        self.project = SimpleNamespace(arch=SimpleNamespace())
        self.cstyle_null_cmp = False

    def next_idx(self, _name):
        self._idx += 1
        return self._idx


def _make_var(name: str, addr: int):
    codegen = _DummyCodegen()
    return _decompile.structured_c.CVariable(
        _decompile.SimMemoryVariable(addr, 1, name=name),
        codegen=codegen,
    )


def _make_stack_var(name: str, offset: int):
    codegen = _DummyCodegen()
    return _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(offset, 1, base="bp", name=name, region=0x1000),
        codegen=codegen,
    )


def test_widening_model_rejects_adjacent_memory_slices_without_stable_identity():
    low = _make_var("field_0", 0x2000)
    high = _make_var("field_1", 0x2001)

    analysis = analyze_adjacent_storage_slices(low, high)

    assert not analysis.ok
    assert analysis.reason == "domain_mismatch"
    assert not can_join_adjacent_storage_slices(low, high)
    assert merge_storage_slice_domains(low, high) == _StorageDomainSignature("mixed")


def test_widening_model_rejects_non_adjacent_memory_slices():
    low = _make_var("field_0", 0x2000)
    far = _make_var("field_2", 0x2002)

    assert not can_join_adjacent_storage_slices(low, far)


def _make_register_var(name: str):
    codegen = _DummyCodegen()
    return _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(30, 1, name=name),
        codegen=codegen,
    )


def test_widening_model_accepts_adjacent_register_slices():
    low = _make_register_var("al")
    high = _make_register_var("ah")

    analysis = analyze_adjacent_storage_slices(low, high)

    assert analysis.ok
    assert analysis.same_domain()
    assert analysis.compatible_view()
    assert can_join_adjacent_storage_slices(low, high)
    assert merge_storage_slice_domains(low, high) == _StorageDomainSignature("register", 2, _StorageView(0, 16))
    assert WideningCandidate.from_expr(low).domain == _StorageDomainSignature("register", 1, _StorageView(0, 8))
    low_candidate = WideningCandidate(_StorageDomainSignature("register", 1, _StorageView(0, 8)), _StorageView(0, 8), low)
    high_candidate = WideningCandidate(_StorageDomainSignature("register", 1, _StorageView(8, 8)), _StorageView(8, 8), high)
    assert low_candidate.is_joinable_with(high_candidate)


def test_widening_model_accepts_adjacent_stack_slices():
    low = _make_stack_var("field_0", -4)
    high = _make_stack_var("field_1", -3)

    assert can_join_adjacent_storage_slices(low, high)
    merged = merge_storage_slice_domains(low, high)
    assert merged == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))
    assert merged.stack_slot == _StackSlotIdentity("bp", -4, 2, region=0x1000)


def test_widening_model_accepts_adjacent_bp_and_ss_stack_slices():
    codegen = _DummyCodegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-4, 1, base="bp", name="field_0", region=0x1000),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(-3, 1, base="ss", name="field_1", region=0x1000),
        codegen=codegen,
    )

    assert can_join_adjacent_storage_slices(low, high)
    merged = merge_storage_slice_domains(low, high)
    assert merged == _StorageDomainSignature("stack", 2, _StorageView(-32, 16))
    assert merged.stack_slot == _StackSlotIdentity("bp", -4, 2, region=0x1000)


def test_widening_model_rejects_mixed_expressions():
    codegen = _DummyCodegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    reg_var = _decompile.SimRegisterVariable(30, 2, name="v14")
    stack_expr = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    reg_expr = _decompile.structured_c.CVariable(reg_var, codegen=codegen)
    mixed = _decompile.structured_c.CBinaryOp("Add", stack_expr, reg_expr, codegen=codegen)

    assert not can_join_adjacent_storage_slices(mixed, reg_expr)
    assert not can_join_adjacent_storage_slices(stack_expr, mixed)
