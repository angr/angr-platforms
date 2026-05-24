import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen import c as structured_c
from angr.sim_type import SimTypeShort
from angr.sim_variable import SimRegisterVariable, SimStackVariable

from angr_platforms.X86_16.arch_86_16 import Arch86_16

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

from angr_platforms.X86_16 import decompiler_postprocess as postprocess  # noqa: E402
from angr_platforms.X86_16.annotations import _normalize_arg_names as _normalize_annotation_arg_names  # noqa: E402
from angr_platforms.X86_16.decompiler_postprocess import (  # noqa: E402
    _apply_annotations_8616,
    _normalize_arg_names_8616,
    _normalize_function_prototype_arg_names_8616,
)
from angr_platforms.X86_16.decompiler_postprocess_stage import (  # noqa: E402
    DECOMPILER_POSTPROCESS_PASSES,
    _decompiler_postprocess_passes_for_function,
)


class _DummyFunction:
    def __init__(self, addr: int, *, call_sites=(), info=None):
        self.addr = addr
        self.info = info or {}
        self._call_sites = tuple(call_sites)

    def get_call_sites(self):
        return self._call_sites


class _FakeInsn:
    def __init__(self, mnemonic: str, op_str: str):
        self.mnemonic = mnemonic
        self.op_str = op_str


class _FakeBlock:
    def __init__(self, insns):
        self.capstone = SimpleNamespace(insns=tuple(insns))


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0):  # noqa: ARG002
        return self._blocks[addr]


class _FakeProject:
    def __init__(self, blocks):
        self.factory = _FakeFactory(blocks)


def test_tiny_function_with_only_call_sites_can_still_be_wrapper_like():
    function = _DummyFunction(0x1000, call_sites=(0x1010,), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)
    options = _decompile._preferred_decompiler_options(1, 24, wrapper_like=profile["wrapper_like"])

    assert profile["call_site_count"] == 1
    assert profile["wrapper_like"] is True
    assert options == [("structurer_cls", "Phoenix")]


def test_tiny_wrapper_like_profile_selects_cheaper_structurer():
    function = _DummyFunction(0x1000, call_sites=(), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)
    options = _decompile._preferred_decompiler_options(1, 24, wrapper_like=profile["wrapper_like"])

    assert profile["wrapper_like"] is True
    assert options == [("structurer_cls", "Phoenix")]


def test_single_block_helper_with_absolute_memory_traffic_is_not_wrapper_like():
    blocks = {
        0x1000: _FakeBlock(
            [
                _FakeInsn("push", "bp"),
                _FakeInsn("mov", "bp, sp"),
                _FakeInsn("mov", "byte ptr [0x7000], 0x48"),
                _FakeInsn("call", "0x101c"),
            ]
        )
    }
    function = _DummyFunction(0x1000, call_sites=(), info={})
    function.project = _FakeProject(blocks)
    function.block_addrs_set = {0x1000}

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)

    assert profile["wrapper_like"] is False
    assert profile["internal_call_count"] == 1


def test_single_block_helper_with_internal_call_is_not_wrapper_like():
    blocks = {
        0x1000: _FakeBlock(
            [
                _FakeInsn("push", "bp"),
                _FakeInsn("mov", "bp, sp"),
                _FakeInsn("call", "0x101c"),
                _FakeInsn("ret", ""),
            ]
        )
    }
    function = _DummyFunction(0x1000, call_sites=(), info={})
    function.project = _FakeProject(blocks)
    function.block_addrs_set = {0x1000}

    profile = _decompile._function_decompilation_profile(function, block_count=1, byte_count=24)

    assert profile["wrapper_like"] is False
    assert profile["internal_call_count"] == 1


def test_tiny_wrapper_like_postprocess_keeps_argument_normalization():
    function = _DummyFunction(
        0x1000,
        info={"x86_16_decompilation_profile": {"wrapper_like": True}},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None))
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr))

    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)

    assert tuple(spec.name for spec in pass_specs) == (
        "_apply_word_global_types_8616",
        "_apply_annotations_8616",
        "_promote_stack_prototype_from_bp_loads_8616",
        "_prune_return_address_stack_arguments_8616",
        "_prune_unused_unnamed_memory_declarations_8616",
        "_rewrite_decoded_jcc_conditions_8616",
        "_rewrite_flag_condition_pairs_8616",
        "_rewrite_flag_bit_value_uses_8616",
        "_prune_unused_flag_assignments_8616",
        "_prune_overwritten_flag_assignments_8616",
        "_fix_interval_guard_conditions_8616",
        "_lower_stable_ss_stack_accesses_8616",
        "_attach_callsite_summaries_8616",
        "_materialize_callsite_stack_arguments_8616",
        "_materialize_callsite_prototypes_8616",
        "_normalize_call_target_names_8616",
    )


def test_call_heavy_small_function_postprocess_keeps_full_pass_list():
    function = _DummyFunction(
        0x1000,
        info={"x86_16_decompilation_profile": {"wrapper_like": False}},
    )
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None))
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=function.addr))

    pass_specs = _decompiler_postprocess_passes_for_function(project, codegen)

    assert tuple(spec.name for spec in pass_specs) == tuple(spec.name for spec in DECOMPILER_POSTPROCESS_PASSES)


def test_call_heavy_small_function_profile_is_not_marked_wrapper_like():
    function = _DummyFunction(0x1000, call_sites=(0x1010,), info={})

    profile = _decompile._function_decompilation_profile(function, block_count=4, byte_count=48)
    options = _decompile._preferred_decompiler_options(4, 48, wrapper_like=profile["wrapper_like"])

    assert profile["wrapper_like"] is False
    assert options is None


def test_linear_region_inference_keeps_early_return_fallthrough_code():
    path = REPO_ROOT / "cod" / "f14" / "CARR.COD"
    entries = _decompile.extract_cod_function_entries(path, "_SetHook", "NEAR")
    selected_entries = _decompile.extract_small_two_arg_cod_logic_entries(entries)
    if selected_entries is None:
        selected_entries = _decompile.extract_simple_cod_logic_entries(entries)
    if selected_entries is None:
        logic_start = _decompile.infer_cod_logic_start(entries)
        proc_code, _ = _decompile.join_cod_entries_with_synthetic_globals(entries, start_offset=logic_start)
    else:
        proc_code, _ = _decompile.join_cod_entries_with_synthetic_globals(selected_entries)

    project = _decompile._build_project_from_bytes(proc_code, base_addr=0x1000, entry_point=0x1000)
    region = _decompile._infer_x86_16_linear_region(project, 0x1000, window=len(proc_code))

    assert region == (0x1000, 0x1033)


def test_normalize_arg_names_makes_duplicates_unique():
    assert _normalize_arg_names_8616(("s", "s", None), 3) == ["s", "s_2", "a2"]


def test_annotation_arg_names_are_normalized_before_assignment():
    assert _normalize_annotation_arg_names(["s", "s", None], 3) == ["s", "s_2", "a2"]


def test_normalize_function_prototype_arg_names_pass_updates_duplicates():
    from angr.sim_type import SimTypeShort

    class _DummyPrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = arg_names
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    prototype = _DummyPrototype([SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False), arg_names=("s", "s"))
    func = SimpleNamespace(prototype=prototype)
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000, prototype=prototype))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None)),
    )

    changed = _normalize_function_prototype_arg_names_8616(project, codegen)

    assert changed is True
    assert func.prototype.arg_names == ["s", "s_2"]
    assert codegen.cfunc.prototype.arg_names == ["s", "s_2"]


def test_attach_cod_variable_names_deduplicates_stack_aliases():
    stack_a = SimStackVariable(-6, 2, base="bp", name="v0", region=0x1000)
    stack_b = SimStackVariable(-2, 2, base="bp", name="v1", region=0x1000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            variables_in_use={
                stack_a: SimpleNamespace(unified_variable=SimpleNamespace(name="v0")),
                stack_b: SimpleNamespace(unified_variable=SimpleNamespace(name="v1")),
            }
        )
    )
    cod_metadata = SimpleNamespace(stack_aliases={-6: "err", -2: "err"})

    changed = _decompile._attach_cod_variable_names(codegen, cod_metadata)
    changed_again = _decompile._attach_cod_variable_names(codegen, cod_metadata)

    assert changed is True
    assert changed_again is False
    assert stack_a.name == "err"
    assert stack_b.name == "err_2"
    assert codegen.cfunc.variables_in_use[stack_a].unified_variable.name == "err"
    assert codegen.cfunc.variables_in_use[stack_b].unified_variable.name == "err_2"


def test_apply_annotations_deduplicates_stack_variable_names():
    from angr.analyses.decompiler.structured_codegen import c as structured_c

    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    stack_a = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    stack_b = SimStackVariable(6, 2, base="bp", name="s", region=0x1000)
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([], codegen=_FakeCodegen()),
            variables_in_use={
                stack_a: SimpleNamespace(unified_variable=SimpleNamespace(name="s")),
                stack_b: SimpleNamespace(unified_variable=SimpleNamespace(name="s")),
            },
        )
    )
    func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {4: {"name": "s"}}}})
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None))
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert stack_a.name == "s"
    assert stack_b.name == "s_2"
    assert codegen.cfunc.variables_in_use[stack_a].unified_variable.name == "s"
    assert codegen.cfunc.variables_in_use[stack_b].unified_variable.name == "s_2"


def test_materialize_missing_register_local_declarations_recovers_unified_locals():
    register = SimRegisterVariable(0, 2, name="a1", region=0x1000)
    class _HashableCVar(SimpleNamespace):
        __hash__ = object.__hash__

    cvar = _HashableCVar(variable_type=SimTypeShort(False), unified_variable=SimpleNamespace(name="a1"))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            unified_local_vars={},
            variables_in_use={register: cvar},
        )
    )

    changed = _decompile._materialize_missing_register_local_declarations(codegen)

    assert changed is True
    assert register in codegen.cfunc.unified_local_vars
    assert len(codegen.cfunc.unified_local_vars[register]) == 1


def test_dedupe_codegen_variable_names_prefers_meaningful_name_and_uniquifies():
    stack_a = SimStackVariable(4, 2, base="bp", name="count", region=0x1000)
    stack_b = SimStackVariable(6, 2, base="bp", name="count", region=0x1000)
    cvar_a = SimpleNamespace(name="v1", unified_variable=SimpleNamespace(name="count"))
    cvar_b = SimpleNamespace(name="v2", unified_variable=SimpleNamespace(name="count"))
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            arg_list=(),
            unified_local_vars={},
            variables_in_use={stack_a: cvar_a, stack_b: cvar_b},
            sort_local_vars=lambda: None,
        )
    )

    changed = _decompile._dedupe_codegen_variable_names_8616(codegen)

    assert changed is True
    assert stack_a.name == "count"
    assert stack_b.name == "count_2"
    assert cvar_a.name == "count"
    assert cvar_b.name == "count_2"


def test_apply_annotations_resolves_direct_bp_stack_loads_to_annotated_slots(monkeypatch):
    class _FakeCodegen:
        def __init__(self, project):
            self._idx = 0
            self.project = project

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    project_stub = SimpleNamespace(arch=SimpleNamespace())
    stack_var = SimStackVariable(4, 2, base="bp", name="s", region=0x1000)
    stack_cvar = structured_c.CVariable(stack_var, variable_type=SimTypeShort(False), codegen=_FakeCodegen(project_stub))
    bp_stack_load = structured_c.CUnaryOp(
        "Dereference",
        structured_c.CConstant(0, SimTypeShort(False), codegen=_FakeCodegen(project_stub)),
        codegen=_FakeCodegen(project_stub),
    )
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            addr=0x1000,
            statements=structured_c.CStatements([bp_stack_load], codegen=_FakeCodegen(project_stub)),
            variables_in_use={stack_var: stack_cvar},
        )
    )
    func = SimpleNamespace(info={"x86_16_annotations": {"stack_vars": {4: {"name": "s"}}}})
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None))
    )

    monkeypatch.setattr(
        postprocess,
        "_match_bp_stack_load_8616",
        lambda node, _project: 5 if node is bp_stack_load else None,
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert codegen.cfunc.statements.statements[0] is stack_cvar


def test_apply_annotations_materializes_stack_arguments_from_annotations():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    class _FakePrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = tuple(arg_names or ())
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    codegen = _FakeCodegen()
    prototype = _FakePrototype([], SimTypeShort(False))
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=codegen),
        variables_in_use={},
        arg_list=[],
        functy=prototype,
    )
    codegen.project = SimpleNamespace(arch=Arch86_16())
    func = SimpleNamespace(
        prototype=prototype,
        info={"x86_16_annotations": {"stack_vars": {2: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None))
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["segment"]
    assert isinstance(codegen.cfunc.arg_list[0], structured_c.CVariable)
    assert codegen.cfunc.arg_list[0].variable.offset == 2
    assert codegen.cfunc.functy.arg_names == ("segment",)


def test_apply_annotations_shrinks_overguessed_stack_arguments():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    class _FakePrototype:
        def __init__(self, args, returnty, *, arg_names=None, variadic=False):
            self.args = list(args)
            self.returnty = returnty
            self.arg_names = tuple(arg_names or ())
            self.variadic = variadic

        def with_arch(self, _arch):
            return self

    codegen = _FakeCodegen()
    prototype = _FakePrototype([SimTypeShort(False), SimTypeShort(False)], SimTypeShort(False), arg_names=("a0", "a1"))
    codegen.cfunc = SimpleNamespace(
        addr=0x1000,
        statements=structured_c.CStatements([], codegen=codegen),
        variables_in_use={},
        arg_list=[],
        functy=prototype,
        prototype=prototype,
    )
    codegen.project = SimpleNamespace(arch=Arch86_16())
    func = SimpleNamespace(
        prototype=prototype,
        info={"x86_16_annotations": {"stack_vars": {2: {"name": "segment"}}}},
    )
    project = SimpleNamespace(
        arch=Arch86_16(),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: func if addr == 0x1000 else None))
    )

    changed = _apply_annotations_8616(project, codegen)

    assert changed is True
    assert [arg.name for arg in codegen.cfunc.arg_list] == ["segment"]
    assert codegen.cfunc.functy.arg_names == ("segment",)
    assert len(codegen.cfunc.functy.args) == 1


def test_simplify_structured_expressions_rewrites_far_pointer_stack_pairs_to_mk_fp():
    class _FakeCodegen:
        def __init__(self):
            self._idx = 0

        def next_idx(self, _name):
            self._idx += 1
            return self._idx

    codegen = _FakeCodegen()
    codegen.project = SimpleNamespace(arch=SimpleNamespace())
    codegen.cstyle_null_cmp = False
    offset_var = SimStackVariable(-0xA, 2, base="bp", name="ovlHeader_2", region=0x1000)
    segment_var = SimStackVariable(-0x8, 2, base="bp", name="ovlHeader", region=0x1000)
    slot_var = SimStackVariable(-0x6, 2, base="bp", name="slotArray_2", region=0x1000)
    segment_source = SimRegisterVariable(0x10, 2, name="ovlLoadSegment")
    offset_cvar = structured_c.CVariable(offset_var, variable_type=SimTypeShort(False), codegen=codegen)
    segment_cvar = structured_c.CVariable(segment_var, variable_type=SimTypeShort(False), codegen=codegen)
    slot_cvar = structured_c.CVariable(slot_var, variable_type=SimTypeShort(False), codegen=codegen)
    segment_source_cvar = structured_c.CVariable(segment_source, variable_type=SimTypeShort(False), codegen=codegen)
    stmts = structured_c.CStatements(
        [
            structured_c.CAssignment(offset_cvar, structured_c.CConstant(0, SimTypeShort(False), codegen=codegen), codegen=codegen),
            structured_c.CAssignment(segment_cvar, segment_source_cvar, codegen=codegen),
            structured_c.CAssignment(
                slot_cvar,
                structured_c.CBinaryOp(
                    "Add",
                    offset_cvar,
                    structured_c.CConstant(36, SimTypeShort(False), codegen=codegen),
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=stmts)

    changed = _decompile._simplify_structured_c_expressions(codegen)

    assert changed is True
    rhs = codegen.cfunc.statements.statements[2].rhs
    assert isinstance(rhs, structured_c.CFunctionCall)
    assert rhs.callee_target == "MK_FP"
