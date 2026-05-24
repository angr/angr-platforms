import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

import archinfo

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)


def test_not_of_bitmask_simplifies_to_zero_compare():
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cstyle_null_cmp=False,
    )
    lhs = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(2, 2, name="Status"),
        codegen=codegen,
    )
    rhs = _decompile.structured_c.CConstant(1, _decompile.SimTypeShort(False), codegen=codegen)
    expr = _decompile.structured_c.CUnaryOp(
        "Not",
        _decompile.structured_c.CBinaryOp("And", lhs, rhs, codegen=codegen),
        codegen=codegen,
    )

    simplified = _decompile._simplify_boolean_expr(expr, codegen)

    assert isinstance(simplified, _decompile.structured_c.CBinaryOp)
    assert simplified.op == "CmpEQ"
    assert isinstance(simplified.rhs, _decompile.structured_c.CConstant)
    assert simplified.rhs.value == 0
    assert simplified.lhs.op == "And"


def test_high_byte_projection_constant_helper_is_shared():
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cstyle_null_cmp=False,
    )
    low = _decompile.structured_c.CBinaryOp(
        "And",
        _decompile.structured_c.CConstant(0x0034, _decompile.SimTypeShort(False), codegen=codegen),
        _decompile.structured_c.CConstant(0x00FF, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    high = _decompile.structured_c.CConstant(0x1200, _decompile.SimTypeShort(False), codegen=codegen)
    expr = _decompile.structured_c.CBinaryOp(
        "And",
        _decompile.structured_c.CBinaryOp("Shr", _decompile.structured_c.CBinaryOp("Or", low, high, codegen=codegen), _decompile.structured_c.CConstant(8, _decompile.SimTypeShort(False), codegen=codegen), codegen=codegen),
        _decompile.structured_c.CConstant(0x00FF, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert _decompile._match_high_byte_projection_constant(expr) == 0x12


def test_widening_analysis_helper_handles_linear_and_projection_forms():
    codegen = SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cstyle_null_cmp=False,
    )
    base = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(30, 2, name="ax"),
        codegen=codegen,
    )
    linear = _decompile.structured_c.CBinaryOp(
        "Add",
        base,
        _decompile.structured_c.CConstant(4, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    projected = _decompile.structured_c.CBinaryOp(
        "Or",
        _decompile.structured_c.CBinaryOp(
            "And",
            base,
            _decompile.structured_c.CConstant(0x00FF, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        _decompile.structured_c.CBinaryOp(
            "Mul",
            _decompile.structured_c.CBinaryOp(
                "Add",
                base,
                _decompile.structured_c.CConstant(1, _decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CConstant(0x100, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        codegen=codegen,
    )
    duplicate_word = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CBinaryOp(
            "Or",
            base,
            _decompile.structured_c.CBinaryOp(
                "Mul",
                base,
                _decompile.structured_c.CConstant(0x100, _decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _decompile.structured_c.CConstant(1, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    mismatched_word = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CBinaryOp(
            "Or",
            base,
            _decompile.structured_c.CBinaryOp(
                "Mul",
                _decompile.structured_c.CVariable(
                    _decompile.SimRegisterVariable(31, 2, name="bx"),
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x100, _decompile.SimTypeShort(False), codegen=codegen),
                codegen=codegen,
            ),
            codegen=codegen,
        ),
        _decompile.structured_c.CConstant(1, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    linear_match = _decompile._analyze_widening_expr(
        linear,
        lambda expr: expr,
        lambda expr: expr,
    )
    projection_match = _decompile._analyze_widening_expr(
        projected,
        lambda expr: expr,
        lambda expr: expr,
    )
    duplicate_word_match = _decompile._analyze_widening_expr(
        duplicate_word,
        lambda expr: expr,
        lambda expr: expr,
    )
    mismatched_word_match = _decompile._analyze_widening_expr(
        mismatched_word,
        lambda expr: expr,
        lambda expr: expr,
    )

    assert linear_match is not None
    assert linear_match.kind == "linear"
    assert linear_match.base_expr is base
    assert linear_match.delta == 4
    assert projection_match is not None
    assert projection_match.kind == "high_byte_preserving"
    assert projection_match.delta == 0x100
    assert duplicate_word_match is not None
    assert duplicate_word_match.kind == "linear"
    assert duplicate_word_match.base_expr is base
    assert duplicate_word_match.delta == 1
    assert mismatched_word_match is None
