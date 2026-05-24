"""
Test expression simplification patterns:
1. Identity AND/OR: var & var → var, var | var → var
"""

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


def make_codegen():
    """Create a minimal codegen object for testing."""
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cfunc=SimpleNamespace(statements=None),
        cstyle_null_cmp=False,
    )


class TestIdentitySimplifications:
    """Test simplifications of identity operations: x op x → x"""

    def test_identity_and_simplifies(self):
        """Test: var & var → var"""
        codegen = make_codegen()

        var = _decompile.structured_c.CVariable(
            _decompile.SimRegisterVariable(30, 2, name="ax"),
            codegen=codegen,
        )
        # Create And with same variable on both sides
        expr = _decompile.structured_c.CBinaryOp("And", var, var, codegen=codegen)

        from angr_platforms.X86_16.decompiler_postprocess_simplify import (
            _simplify_structured_expressions_8616,
        )

        codegen.cfunc.statements = expr
        changed = _simplify_structured_expressions_8616(codegen)

        result = codegen.cfunc.statements
        # Should simplify to just the variable
        assert isinstance(result, _decompile.structured_c.CVariable)
        assert result.name == "ax"

    def test_identity_or_simplifies(self):
        """Test: var | var → var"""
        codegen = make_codegen()

        var = _decompile.structured_c.CVariable(
            _decompile.SimRegisterVariable(30, 2, name="bx"),
            codegen=codegen,
        )
        # Create Or with same variable on both sides
        expr = _decompile.structured_c.CBinaryOp("Or", var, var, codegen=codegen)

        from angr_platforms.X86_16.decompiler_postprocess_simplify import (
            _simplify_structured_expressions_8616,
        )

        codegen.cfunc.statements = expr
        changed = _simplify_structured_expressions_8616(codegen)

        result = codegen.cfunc.statements
        # Should simplify to just the variable
        assert isinstance(result, _decompile.structured_c.CVariable)
        assert result.name == "bx"

    def test_identity_logical_and_simplifies(self):
        """Test: var && var → var"""
        codegen = make_codegen()

        var = _decompile.structured_c.CVariable(
            _decompile.SimRegisterVariable(30, 2, name="cx"),
            codegen=codegen,
        )
        # Create LogicalAnd with same variable on both sides
        expr = _decompile.structured_c.CBinaryOp(
            "LogicalAnd", var, var, codegen=codegen
        )

        from angr_platforms.X86_16.decompiler_postprocess_simplify import (
            _simplify_structured_expressions_8616,
        )

        codegen.cfunc.statements = expr
        changed = _simplify_structured_expressions_8616(codegen)

        result = codegen.cfunc.statements
        # Should simplify to just the variable
        assert isinstance(result, _decompile.structured_c.CVariable)
        assert result.name == "cx"

    def test_identity_logical_or_simplifies(self):
        """Test: var || var → var"""
        codegen = make_codegen()

        var = _decompile.structured_c.CVariable(
            _decompile.SimRegisterVariable(30, 2, name="dx"),
            codegen=codegen,
        )
        # Create LogicalOr with same variable on both sides
        expr = _decompile.structured_c.CBinaryOp(
            "LogicalOr", var, var, codegen=codegen
        )

        from angr_platforms.X86_16.decompiler_postprocess_simplify import (
            _simplify_structured_expressions_8616,
        )

        codegen.cfunc.statements = expr
        changed = _simplify_structured_expressions_8616(codegen)

        result = codegen.cfunc.statements
        # Should simplify to just the variable
        assert isinstance(result, _decompile.structured_c.CVariable)
        assert result.name == "dx"
