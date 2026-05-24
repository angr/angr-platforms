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

_access_trait_member_candidates = _decompile._access_trait_member_candidates
_attach_access_trait_field_names = _decompile._attach_access_trait_field_names
_AccessTraitRewriteDecision = _decompile._AccessTraitRewriteDecision
_AccessTraitEvidenceProfile = _decompile._AccessTraitEvidenceProfile


def test_access_trait_array_evidence_feeds_member_candidates():
    traits = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "member_evidence": {},
        "array_evidence": {
            (("reg", 4), ("reg", 2), 4, 0, 2): 1,
        },
    }

    candidates = _access_trait_member_candidates(traits)

    assert candidates == {("reg", 4): [(0, 2, 1)]}


def test_access_trait_array_evidence_can_rename_stack_objects():
    class DummyCodegen:
        def __init__(self):
            self._i = 0
            self.project = SimpleNamespace(arch=SimpleNamespace())
            self.cfunc = SimpleNamespace(addr=0x1000, name="_ConfigCrts")

        def next_idx(self, _):
            self._i += 1
            return self._i

    codegen = DummyCodegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    cvar = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    codegen.cfunc.variables_in_use = {stack_var: cvar}
    codegen.cfunc.statements = cvar
    project = SimpleNamespace(
        _inertia_access_traits={
            0x1000: {
                "base_const": {},
                "base_stride": {},
                "repeated_offsets": {},
                "repeated_offset_widths": {},
                "base_stride_widths": {},
                "member_evidence": {},
                "array_evidence": {
                    (("stack", "bp", -4), ("reg", 2), 2, 4, 2): 1,
                },
            }
        }
    )
    codegen.project = project

    changed = _attach_access_trait_field_names(project, codegen)

    assert changed
    assert stack_var.name == "field_0"
    assert cvar.name == "field_0"


def test_access_trait_stack_like_evidence_uses_stack_object_naming():
    class DummyCodegen:
        def __init__(self):
            self._i = 0
            self.project = SimpleNamespace(arch=SimpleNamespace())
            self.cfunc = SimpleNamespace(addr=0x1000, name="_ConfigCrts")

        def next_idx(self, _):
            self._i += 1
            return self._i

    codegen = DummyCodegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    cvar = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    codegen.cfunc.variables_in_use = {stack_var: cvar}
    codegen.cfunc.statements = cvar
    project = SimpleNamespace(
        _inertia_access_traits={
            0x1000: {
                "base_const": {
                    ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
                },
                "base_stride": {},
                "repeated_offsets": {},
                "repeated_offset_widths": {},
                "base_stride_widths": {},
                "member_evidence": {},
                "array_evidence": {},
            }
        }
    )
    codegen.project = project

    changed = _attach_access_trait_field_names(project, codegen)

    assert changed
    assert stack_var.name == "local_4"
    assert cvar.name == "local_4"


def test_access_trait_rewrite_decision_separates_evidence_kinds():
    member_profile = _AccessTraitEvidenceProfile(member_like=((4, 2, 3),))
    array_profile = _AccessTraitEvidenceProfile(array_like=((0, 2, 5),))
    mixed_profile = _AccessTraitEvidenceProfile(member_like=((4, 2, 3),), array_like=((0, 2, 5),))

    assert _AccessTraitRewriteDecision(("stack", "bp", -4), member_profile).preferred_kind() == "member"
    assert _AccessTraitRewriteDecision(("stack", "bp", -4), array_profile).preferred_kind() == "array"
    assert _AccessTraitRewriteDecision(("stack", "bp", -4), mixed_profile).preferred_kind() is None
    assert _AccessTraitRewriteDecision(("stack", "bp", -4), mixed_profile).candidate_field_names() == ()


def test_mixed_access_trait_evidence_does_not_rename_stack_object():
    class DummyCodegen:
        def __init__(self):
            self._i = 0
            self.project = SimpleNamespace(arch=SimpleNamespace())
            self.cfunc = SimpleNamespace(addr=0x1000, name="_ConfigCrts")

        def next_idx(self, _):
            self._i += 1
            return self._i

    codegen = DummyCodegen()
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    cvar = _decompile.structured_c.CVariable(stack_var, codegen=codegen)
    codegen.cfunc.variables_in_use = {stack_var: cvar}
    codegen.cfunc.statements = cvar
    project = SimpleNamespace(
        _inertia_access_traits={
            0x1000: {
                "base_const": {
                    ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
                },
                "base_stride": {},
                "repeated_offsets": {},
                "repeated_offset_widths": {},
                "base_stride_widths": {},
                "member_evidence": {},
                "array_evidence": {
                    (("stack", "bp", -4), ("reg", 2), 2, 4, 2): 1,
                },
            }
        }
    )
    codegen.project = project

    changed = _attach_access_trait_field_names(project, codegen)

    assert not changed
    assert stack_var.name == "v1"
    assert cvar.name == "v1"
