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

_should_attach_access_trait_names = _decompile._should_attach_access_trait_names


def make_codegen(name: str, addr: int, traits=None):
    project = SimpleNamespace(_inertia_access_traits={} if traits is None else {addr: traits})
    return SimpleNamespace(project=project, cfunc=SimpleNamespace(name=name, addr=addr))


def test_access_trait_rewrite_policy_requires_collected_evidence():
    assert not _should_attach_access_trait_names(make_codegen("_ConfigCrts", 0x1000))
    assert not _should_attach_access_trait_names(make_codegen("_UnlistedProc", 0x1000))


def test_access_trait_rewrite_policy_is_evidence_driven_not_name_driven():
    traits = {
        "base_const": {
            ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
        },
    }

    assert _should_attach_access_trait_names(make_codegen("_UnlistedProc", 0x1000, traits))


def test_access_trait_rewrite_policy_requires_stable_object_hint_not_mixed_trait_noise():
    traits = {
        "base_const": {
            ("ss", ("stack", "bp", -4), 4, 2, 1): 1,
        },
        "array_evidence": {
            (("stack", "bp", -4), ("reg", 2), 4, 0, 2): 1,
        },
    }

    assert not _should_attach_access_trait_names(make_codegen("_UnlistedProc", 0x1000, traits))
