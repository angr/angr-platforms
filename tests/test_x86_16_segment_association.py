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


def _make_codegen():
    return SimpleNamespace(
        next_idx=lambda _name: 1,
        project=SimpleNamespace(arch=archinfo.ArchX86()),
        cstyle_null_cmp=False,
    )


def _make_segmented_expr(stack_vars, *, seg_name="es", offset=0):
    codegen = _make_codegen()
    seg_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            codegen.project.arch.registers[seg_name][0],
            2,
            name=seg_name,
        ),
        codegen=codegen,
    )
    seg_part = _decompile.structured_c.CBinaryOp(
        "Mul",
        seg_reg,
        _decompile.structured_c.CConstant(16, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr = seg_part
    for stack_var in stack_vars:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CVariable(stack_var, codegen=codegen),
            codegen=codegen,
        )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return expr


def _make_segmented_expr_shl(stack_vars, *, seg_name="es", offset=0):
    codegen = _make_codegen()
    seg_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            codegen.project.arch.registers[seg_name][0],
            2,
            name=seg_name,
        ),
        codegen=codegen,
    )
    seg_part = _decompile.structured_c.CBinaryOp(
        "Shl",
        seg_reg,
        _decompile.structured_c.CConstant(4, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr = seg_part
    for stack_var in stack_vars:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CVariable(stack_var, codegen=codegen),
            codegen=codegen,
        )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return expr


def _make_segmented_expr_from_reg_shl(reg_name: str, *, seg_name="ds", offset=0):
    codegen = _make_codegen()
    project = codegen.project
    seg_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            project.arch.registers[seg_name][0],
            2,
            name=seg_name,
        ),
        codegen=codegen,
    )
    base_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            project.arch.registers[reg_name][0],
            2,
            name=reg_name,
        ),
        codegen=codegen,
    )
    expr = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CBinaryOp(
            "Shl",
            seg_reg,
            _decompile.structured_c.CConstant(4, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        base_reg,
        codegen=codegen,
    )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return project, codegen, expr


def _make_segmented_expr_from_reg(reg_name: str, *, seg_name="ds", offset=0):
    codegen = _make_codegen()
    project = codegen.project
    seg_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            project.arch.registers[seg_name][0],
            2,
            name=seg_name,
        ),
        codegen=codegen,
    )
    base_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(
            project.arch.registers[reg_name][0],
            2,
            name=reg_name,
        ),
        codegen=codegen,
    )
    expr = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CBinaryOp(
            "Mul",
            seg_reg,
            _decompile.structured_c.CConstant(16, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        base_reg,
        codegen=codegen,
    )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return project, codegen, expr


def _make_segmented_stride_expr_from_reg(reg_name: str, stride: int, *, seg_name="ds", offset=0):
    codegen = _make_codegen()
    project = codegen.project
    seg_reg = _decompile.structured_c.CVariable(
        _decompile.SimRegisterVariable(project.arch.registers[seg_name][0], 2, name=seg_name),
        codegen=codegen,
    )
    base_reg_var = _decompile.SimRegisterVariable(project.arch.registers[reg_name][0], 2, name=reg_name)
    base_reg = _decompile.structured_c.CVariable(
        base_reg_var,
        codegen=codegen,
    )
    scaled = _decompile.structured_c.CBinaryOp(
        "Mul",
        base_reg,
        _decompile.structured_c.CConstant(stride, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )
    expr = _decompile.structured_c.CBinaryOp(
        "Add",
        _decompile.structured_c.CBinaryOp(
            "Mul",
            seg_reg,
            _decompile.structured_c.CConstant(16, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        ),
        scaled,
        codegen=codegen,
    )
    if offset:
        expr = _decompile.structured_c.CBinaryOp(
            "Add",
            expr,
            _decompile.structured_c.CConstant(offset, _decompile.SimTypeShort(False), codegen=codegen),
            codegen=codegen,
        )
    return project, codegen, expr, base_reg_var


def _make_byte_dereference(addr_expr, codegen):
    byte_type = _decompile.SimTypeChar(False)
    ptr_type = _decompile.SimTypePointer(byte_type).with_arch(codegen.project.arch)
    return _decompile.structured_c.CUnaryOp(
        "Dereference",
        _decompile.structured_c.CTypeCast(
            _decompile.SimTypeShort(False),
            ptr_type,
            addr_expr,
            codegen=codegen,
        ),
        codegen=codegen,
    )


def _make_global_byte_var(addr: int, name: str = "g"):
    codegen = _make_codegen()
    return codegen, _decompile.structured_c.CVariable(
        _decompile.SimMemoryVariable(addr, 1, name=name, region=0x1000),
        variable_type=_decompile.SimTypeChar(False),
        codegen=codegen,
    )


def test_segmented_access_classifier_marks_single_stack_base_as_single():
    codegen = _make_codegen()
    project = codegen.project
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    expr = _make_segmented_expr([stack_var], offset=2)

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "es"
    assert classified.assoc_kind == "single"
    assert classified.assoc_state is not None
    assert classified.assoc_state.assoc_kind == "single"
    assert not classified.assoc_state.is_over_associated()
    assert classified.allows_object_rewrite()
    assert classified.extra_offset == 2


def test_segmented_access_classifier_marks_multiple_stack_bases_as_over():
    codegen = _make_codegen()
    project = codegen.project
    first = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    second = _decompile.SimStackVariable(-8, 2, base="bp", name="v2", region=0x1000)
    expr = _make_segmented_expr([first, second])

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "es"
    assert classified.assoc_kind == "over"
    assert classified.assoc_state is not None
    assert classified.assoc_state.assoc_kind == "over"
    assert classified.assoc_state.is_over_associated()
    assert not classified.allows_object_rewrite()


def test_segmented_access_classifier_tracks_single_stack_slot_as_single():
    codegen = _make_codegen()
    project = codegen.project
    stack_var = _decompile.SimStackVariable(-4, 2, base="bp", name="v1", region=0x1000)
    expr = _make_segmented_expr([stack_var, stack_var])

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.assoc_kind == "single"
    assert classified.assoc_state is not None
    assert classified.assoc_state.assoc_kind == "single"
    assert classified.allows_object_rewrite()


def test_ds_constant_segment_offset_stays_segment_const_not_global():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr([], seg_name="ds", offset=0x234)

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "ds"
    assert classified.kind == "segment_const"
    assert classified.linear == 0x234


def test_ds_constant_segment_offset_shl_form_stays_segment_const_not_global():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr_shl([], seg_name="ds", offset=0x234)

    classified = _decompile._classify_segmented_addr_expr(expr, project)

    assert classified is not None
    assert classified.seg_name == "ds"
    assert classified.kind == "segment_const"
    assert classified.linear == 0x234


def test_match_real_mode_linear_expr_keeps_ds_identity_visible():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr([], seg_name="ds", offset=0x234)

    assert _decompile._match_real_mode_linear_expr(expr, project) == ("ds", 0x234)


def test_global_load_addr_rejects_segment_const_dereference():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr([], seg_name="ds", offset=0x234)
    deref = _make_byte_dereference(expr, codegen)

    assert _decompile._global_load_addr(deref, project) is None


def test_match_scaled_high_byte_accepts_true_global_variable_only():
    codegen, global_var = _make_global_byte_var(0x234)
    shl = _decompile.structured_c.CBinaryOp(
        "Shl",
        global_var,
        _decompile.structured_c.CConstant(8, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert _decompile._match_scaled_high_byte(shl, codegen.project) == 0x234


def test_match_scaled_high_byte_rejects_segment_const_byte_deref():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr([], seg_name="ds", offset=0x235)
    deref = _make_byte_dereference(expr, codegen)
    shl = _decompile.structured_c.CBinaryOp(
        "Shl",
        deref,
        _decompile.structured_c.CConstant(8, _decompile.SimTypeShort(False), codegen=codegen),
        codegen=codegen,
    )

    assert _decompile._match_scaled_high_byte(shl, project) is None


def test_addr_exprs_are_same_requires_same_segment_space():
    codegen = _make_codegen()
    project = codegen.project
    ds_expr = _make_segmented_expr([], seg_name="ds", offset=0x234)
    es_expr = _make_segmented_expr([], seg_name="es", offset=0x234)

    assert _decompile._addr_exprs_are_same(ds_expr, es_expr, project) is False


def test_addr_exprs_are_byte_pair_requires_same_segment_space():
    codegen = _make_codegen()
    project = codegen.project
    ds_expr = _make_segmented_expr([], seg_name="ds", offset=0x234)
    ds_next = _make_segmented_expr([], seg_name="ds", offset=0x235)
    es_next = _make_segmented_expr([], seg_name="es", offset=0x235)

    assert _decompile._addr_exprs_are_byte_pair(ds_expr, ds_next, project) is True
    assert _decompile._addr_exprs_are_byte_pair(ds_expr, es_next, project) is False


def test_segment_register_based_dereference_refuses_constant_segment_offset():
    codegen = _make_codegen()
    project = codegen.project
    expr = _make_segmented_expr([], seg_name="ds", offset=0x234)
    deref = _decompile.structured_c.CUnaryOp("Dereference", expr, codegen=codegen)

    assert _decompile._match_segment_register_based_dereference(deref, project) is None


def test_segment_register_based_dereference_refuses_unproven_register_base():
    project, codegen, expr = _make_segmented_expr_from_reg("bx", seg_name="ds", offset=4)
    deref = _decompile.structured_c.CUnaryOp("Dereference", expr, codegen=codegen)

    assert _decompile._match_segment_register_based_dereference(deref, project) is None


def test_elide_redundant_segment_pointer_dereferences_refuses_unproven_register_base():
    project, codegen, expr = _make_segmented_expr_from_reg("bx", seg_name="ds", offset=4)
    deref = _make_byte_dereference(expr, codegen)
    codegen.cfunc = SimpleNamespace(statements=deref)

    changed = _decompile._elide_redundant_segment_pointer_dereferences(project, codegen)

    assert changed is False
    assert codegen.cfunc.statements is deref


def test_collect_access_traits_refuses_segment_stride_without_proven_base():
    project, codegen, expr, _base_reg_var = _make_segmented_stride_expr_from_reg("bx", 4, seg_name="ds", offset=0)
    deref = _make_byte_dereference(expr, codegen)
    codegen.cfunc = SimpleNamespace(statements=deref, addr=0x1000)
    project._inertia_access_traits = {}

    _decompile._collect_access_traits(project, codegen)

    traits = project._inertia_access_traits[0x1000]
    assert traits["base_stride"] == {}
    assert traits["base_stride_widths"] == {}
    assert traits["stride_evidence"] == {}
    assert traits["array_evidence"] == {}


def test_attach_pointer_member_names_ignores_segment_stride_without_proven_base():
    project, codegen, expr, base_reg_var = _make_segmented_stride_expr_from_reg("bx", 4, seg_name="ds", offset=0)
    deref = _make_byte_dereference(expr, codegen)
    base_cvar = _decompile.structured_c.CVariable(base_reg_var, codegen=codegen)
    codegen.cfunc = SimpleNamespace(
        statements=deref,
        addr=0x1000,
        variables_in_use={base_reg_var: base_cvar},
    )
    project._inertia_access_traits = {}

    _decompile._collect_access_traits(project, codegen)
    changed = _decompile._attach_pointer_member_names(project, codegen)

    assert changed is False
    assert base_reg_var.name == "bx"
    assert base_cvar.name == "bx"


def test_strip_segment_scale_from_addr_expr_keeps_register_plus_offset():
    project, _codegen, expr = _make_segmented_expr_from_reg("bx", seg_name="ds", offset=4)

    stripped = _decompile._strip_segment_scale_from_addr_expr(expr, project)

    assert stripped is not None
    terms = _decompile._flatten_c_add_terms(stripped)
    names = sorted(
        getattr(getattr(term, "variable", None), "name", None)
        for term in terms
        if isinstance(term, _decompile.structured_c.CVariable)
    )
    constants = sorted(
        term.value
        for term in terms
        if isinstance(term, _decompile.structured_c.CConstant)
    )
    assert names == ["bx"]
    assert constants == [4]


def test_strip_segment_scale_from_addr_expr_keeps_register_plus_offset_for_shl_form():
    project, _codegen, expr = _make_segmented_expr_from_reg_shl("bx", seg_name="ds", offset=4)

    stripped = _decompile._strip_segment_scale_from_addr_expr(expr, project)

    assert stripped is not None
    terms = _decompile._flatten_c_add_terms(stripped)
    names = sorted(
        getattr(getattr(term, "variable", None), "name", None)
        for term in terms
        if isinstance(term, _decompile.structured_c.CVariable)
    )
    constants = sorted(
        term.value
        for term in terms
        if isinstance(term, _decompile.structured_c.CConstant)
    )
    assert names == ["bx"]
    assert constants == [4]
