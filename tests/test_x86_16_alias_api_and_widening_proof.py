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

from angr_platforms.X86_16.alias_domains import AX
from angr_platforms.X86_16.alias_model import (
    can_join_alias_storage,
    compatible_alias_storage_views,
    describe_alias_storage,
    describe_x86_16_alias_recovery_api,
    needs_alias_synthesis,
    same_alias_storage_domain,
)
from angr_platforms.X86_16.alias_state import AliasState
from angr_platforms.X86_16.widening_alias import can_join_adjacent_register_slices
from angr_platforms.X86_16.widening_model import (
    collect_widening_candidates,
    describe_widening_candidates,
    describe_x86_16_widening_pipeline,
    prove_adjacent_storage_slices,
)


def _make_codegen():
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=SimpleNamespace(registers={"ax": (0, 2), "bx": (6, 2), "cx": (2, 2), "dx": (4, 2)})),
        cstyle_null_cmp=False,
    )


def _reg(name: str, reg: int, size: int = 1):
    return _decompile.structured_c.CVariable(_decompile.SimRegisterVariable(reg, size, name=name), codegen=_make_codegen())


def test_alias_api_tracks_register_storage_identity_and_view_compatibility():
    low = _reg("al", 0)
    high = _reg("ah", 1)
    other = _reg("bl", 6)

    assert same_alias_storage_domain(low, high)
    assert compatible_alias_storage_views(low, high)
    assert can_join_alias_storage(low, high)
    assert not same_alias_storage_domain(low, other)
    assert not can_join_alias_storage(low, other)


def test_alias_recovery_api_is_explicit_and_stable():
    api = describe_x86_16_alias_recovery_api()

    assert [name for name, _, _ in api] == ["same_domain", "compatible_view", "needs_synthesis", "can_join"]
    assert api[0][2] == ("same_alias_storage_domain",)


def test_alias_api_marks_mixed_expression_for_synthesis():
    codegen = _make_codegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    reg_var = _decompile.SimRegisterVariable(30, 2, name="v14")
    stack_expr = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    reg_expr = _decompile.structured_c.CVariable(reg_var, codegen=codegen)
    mixed = _decompile.structured_c.CBinaryOp("Add", stack_expr, reg_expr, codegen=codegen)

    assert describe_alias_storage(mixed).domain.space == "mixed"
    assert needs_alias_synthesis(mixed)


def test_widening_candidate_extraction_and_debug_description():
    low = _reg("al", 0)
    high = _reg("ah", 1)
    other = _reg("bl", 6)

    candidates = collect_widening_candidates([low, high, other])

    assert len(candidates) == 3
    descriptions = describe_widening_candidates([low, high, other])
    assert descriptions[0]["domain"].startswith("register")
    assert descriptions[0]["view"]["bit_width"] == 8


def test_constant_mk_fp_literals_are_recovered_as_far_pointer_storage():
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

    facts = describe_alias_storage(expr)
    candidates = collect_widening_candidates([expr])

    assert facts.domain.space == "far_pointer"
    assert facts.identity == ("far_pointer", (0x40, 0x17))
    assert len(candidates) == 1
    assert candidates[0].domain.space == "far_pointer"
    assert candidates[0].view.bit_width == 32


def test_far_pointers_with_same_linear_address_but_different_segments_do_not_alias():
    codegen = _make_codegen()
    lhs = _decompile.structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            _decompile.structured_c.CConstant(0x40, _decompile.SimTypeShort(False), codegen=codegen),
            _decompile.structured_c.CConstant(0x17, _decompile.SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )
    rhs = _decompile.structured_c.CFunctionCall(
        "MK_FP",
        None,
        [
            _decompile.structured_c.CConstant(0x41, _decompile.SimTypeShort(False), codegen=codegen),
            _decompile.structured_c.CConstant(0x07, _decompile.SimTypeShort(False), codegen=codegen),
        ],
        codegen=codegen,
    )

    assert not same_alias_storage_domain(lhs, rhs)
    assert not can_join_alias_storage(lhs, rhs)


def test_alias_api_rejects_adjacent_memory_bytes_without_shared_identity():
    codegen = _make_codegen()
    low = _decompile.structured_c.CVariable(
        _decompile.SimMemoryVariable(0x2000, 1, name="field_0"),
        codegen=codegen,
    )
    high = _decompile.structured_c.CVariable(
        _decompile.SimMemoryVariable(0x2001, 1, name="field_1"),
        codegen=codegen,
    )

    assert same_alias_storage_domain(low, high) is False
    assert can_join_alias_storage(low, high) is False


def test_widening_pipeline_is_explicit_and_stable():
    pipeline = describe_x86_16_widening_pipeline()

    assert [name for name, _, _ in pipeline] == ["candidate_extraction", "compatibility_proof", "join_decision"]
    assert "prove_adjacent_storage_slices" in pipeline[1][2]


def test_widening_proof_accepts_joinable_register_slices_and_rejects_mixed_pairs():
    low = _reg("al", 0)
    high = _reg("ah", 1)
    other = _reg("bl", 6)

    proof = prove_adjacent_storage_slices(low, high)
    rejected = prove_adjacent_storage_slices(low, other)

    assert proof.ok
    assert proof.reason == "ok"
    assert proof.merged_domain is not None
    assert rejected.reason == "domain_mismatch"


def test_widening_proof_can_surface_version_mismatches(monkeypatch):
    low = _reg("al", 0)
    high = _reg("ah", 1)
    state = AliasState()
    state._versions[AX] = 1

    monkeypatch.setattr(
        "angr_platforms.X86_16.widening_model._register_version_for_expr",
        lambda expr, _state: 1 if getattr(expr.variable, "name", "") == "al" else 2,
    )

    proof = prove_adjacent_storage_slices(low, high, alias_state=state)

    assert not proof.ok
    assert proof.reason == "version_mismatch"


def test_register_pair_join_rejects_version_mismatch_when_alias_state_is_available(monkeypatch):
    low = _reg("al", 0)
    high = _reg("ah", 1)
    state = AliasState()
    state._versions[AX] = 1

    monkeypatch.setattr(
        "angr_platforms.X86_16.widening_model._register_version_for_expr",
        lambda expr, _state: 1 if getattr(expr.variable, "name", "") == "al" else 2,
    )

    assert not can_join_adjacent_register_slices(low, high, alias_state=state)


def test_register_pair_join_rejects_missing_version_evidence_when_alias_state_is_available(monkeypatch):
    low = _reg("al", 0)
    high = _reg("ah", 1)
    state = AliasState()
    state._versions[AX] = 1

    def _version_for_expr(expr, _state):
        return 1 if getattr(expr.variable, "name", "") == "al" else None

    monkeypatch.setattr("angr_platforms.X86_16.widening_model._register_version_for_expr", _version_for_expr)

    assert not can_join_adjacent_register_slices(low, high, alias_state=state)


def test_register_pair_join_requires_alias_state():
    low = _reg("al", 0)
    high = _reg("ah", 1)

    assert not can_join_adjacent_register_slices(low, high)
