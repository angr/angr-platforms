import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)


def _make_codegen():
    return SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1000),
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=Arch86_16()),
    )


def test_synthetic_word_global_variable_reuses_created_cache():
    codegen = _make_codegen()
    synthetic_globals = {0x2000: ("word global", 2)}
    created = {}

    first = _decompile._synthetic_word_global_variable(codegen, synthetic_globals, 0x2000, created)
    second = _decompile._synthetic_word_global_variable(codegen, synthetic_globals, 0x2000, created)

    assert first is second
    assert first is created[0x2000]
    assert getattr(first.variable, "name", None) == "word_global"
    assert getattr(first.variable, "addr", None) == 0x2000


def test_synthetic_word_global_variable_rejects_byte_globals():
    codegen = _make_codegen()
    synthetic_globals = {0x2000: ("tiny", 1)}

    assert _decompile._synthetic_word_global_variable(codegen, synthetic_globals, 0x2000) is None
