import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
from types import SimpleNamespace

from angr.sim_type import SimStruct, SimTypeShort

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)


def test_dos_pseudo_callee_attachment_accepts_partial_callnode_matches(monkeypatch):
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(
            statements=SimpleNamespace(),
        )
    )
    codegen.project = SimpleNamespace(arch=_decompile.Arch86_16())
    codegen.next_idx = lambda _name: 1

    first = _decompile.structured_c.CFunctionCall(None, None, [], codegen=codegen)
    second = _decompile.structured_c.CFunctionCall(None, None, [], codegen=codegen)

    fake_helper = SimpleNamespace(name="dos_int21", prototype=None)
    project = SimpleNamespace(
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr: fake_helper if addr == 0x2000 else None))
    )
    function = SimpleNamespace(get_call_target=lambda _addr: 0x2000)

    monkeypatch.setattr(_decompile, "collect_dos_int21_calls", lambda _function: [SimpleNamespace(insn_addr=0x1234)])
    monkeypatch.setattr(_decompile, "_iter_c_nodes", lambda _node: [first, second])

    changed = _decompile._attach_dos_pseudo_callees(project, function, codegen, "pseudo")

    assert changed
    assert first.callee_func is fake_helper
    assert second.callee_func is None


def test_interrupt_service_table_names_cover_common_bios_vectors():
    call_12 = _decompile.InterruptCall(insn_addr=0x1000, vector=0x12)
    call_13 = _decompile.InterruptCall(insn_addr=0x1002, vector=0x13)
    call_1a = _decompile.InterruptCall(insn_addr=0x1004, vector=0x1A)

    assert _decompile.interrupt_service_name(call_12, "pseudo") == "bios_memsize"
    assert _decompile.interrupt_service_name(call_12, "dos") == "_bios_memsize"
    assert _decompile.interrupt_service_name(call_13, "pseudo") == "bios_int13_disk"
    assert _decompile.interrupt_service_name(call_13, "dos") == "_bios_disk"
    assert _decompile.interrupt_service_name(call_1a, "pseudo") == "bios_timeofday"
    assert _decompile.interrupt_service_name(call_1a, "dos") == "_bios_timeofday"


def test_interrupt_service_renderer_uses_table_driven_names():
    call_12 = _decompile.InterruptCall(insn_addr=0x1000, vector=0x12)
    call_13 = _decompile.InterruptCall(insn_addr=0x1002, vector=0x13)

    assert _decompile.render_interrupt_call(call_12, "pseudo") == "bios_memsize()"
    assert _decompile.render_interrupt_call(call_12, "dos") == "_bios_memsize()"
    assert _decompile.render_interrupt_call(call_13, "pseudo") == "bios_int13_disk()"
    assert _decompile.render_interrupt_call(call_13, "dos") == "_bios_disk()"


def test_interrupt_service_renderer_carries_bios_keybrd_selector():
    call = _decompile.InterruptCall(insn_addr=0x1006, vector=0x16, ah=0x02)

    assert _decompile.render_interrupt_call(call, "pseudo") == "bios_keybrd(2)"
    assert _decompile.render_interrupt_call(call, "dos") == "_bios_keybrd(2)"
    assert _decompile.interrupt_service_declarations([call], "dos") == ["unsigned _bios_keybrd(unsigned keycmd);"]


def test_interrupt_service_renderer_covers_vector_management_apis():
    call_get = _decompile.InterruptCall(insn_addr=0x1010, vector=0x21, ah=0x35, al=0x21)
    call_set = _decompile.InterruptCall(insn_addr=0x1012, vector=0x21, ah=0x25, al=0x21, ds=0x1234, dx=0x5678)

    assert _decompile.render_interrupt_call(call_get, "pseudo") == "dos_getvect(0x21)"
    assert _decompile.render_interrupt_call(call_get, "dos") == "_dos_getvect(0x21)"
    assert _decompile.render_interrupt_call(call_get, "modern") == "getvect(0x21)"
    assert _decompile.render_interrupt_call(call_set, "pseudo") == "dos_setvect(0x21, MK_FP(0x1234, 0x5678))"
    assert _decompile.render_interrupt_call(call_set, "dos") == "_dos_setvect(0x21, MK_FP(0x1234, 0x5678))"
    assert _decompile.render_interrupt_call(call_set, "modern") == "setvect(0x21, MK_FP(0x1234, 0x5678))"

    declarations = _decompile.interrupt_service_declarations([call_get, call_set], "modern")
    assert "void (*getvect(int interruptno))(void);" in declarations
    assert "void setvect(int interruptno, void (*isr)(void));" in declarations


def test_interrupt_service_renderer_keeps_int10_wrapper_oriented():
    call = _decompile.InterruptCall(insn_addr=0x1020, vector=0x10, ah=0x0E)
    callx = _decompile.InterruptCall(insn_addr=0x1022, vector=0x10, ah=0x03, ds=0x1111, es=0x2222)
    call_unknown = _decompile.InterruptCall(insn_addr=0x1024, vector=0x10)

    assert _decompile.render_interrupt_call(call, "pseudo") == "bios_int10_video(0xe)"
    assert _decompile.render_interrupt_call(call, "dos") == "_bios_int10_video(0xe)"
    assert _decompile.render_interrupt_call(callx, "pseudo") == "bios_int10_video(3)"
    assert _decompile.render_interrupt_call(call_unknown, "pseudo") == "int86(0x10, &inregs, &outregs)"
    assert _decompile.render_interrupt_call(call_unknown, "dos") == "int86(0x10, &inregs, &outregs)"
    assert _decompile.interrupt_service_declarations([call, callx], "pseudo") == [
        "int bios_int10_video(unsigned int service);"
    ]


def test_interrupt_wrapper_helper_call_expr_carries_bios_int10_selector():
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    sig = _decompile.InterruptWrapperCall(
        callee_name="int86",
        canonical_name="int86",
        kind="int86",
        arguments=(object(), object(), object()),
        vector_arg=_decompile.structured_c.CConstant(0x10, SimTypeShort(), codegen=codegen),
    )
    input_state = {
        "inregs": {
            ("h", "ah"): 0x0F,
        }
    }

    helper = _decompile._interrupt_wrapper_helper_call_expr(sig, input_state, "pseudo", codegen)

    assert helper is not None
    assert helper.callee_target == "bios_int10_video"
    assert [arg.value for arg in helper.args] == [0x0F]


def test_interrupt_wrapper_result_lowering_rewrites_bios_int10_results_with_selector():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x3455, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    regs_struct = SimStruct({"h": h_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    sink = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="sink", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    al_field = _decompile.structured_c.CStructField(h_struct, 1, "al", codegen=codegen)
    sink_ref = _decompile.structured_c.CVariable(sink.variable, variable_type=SimTypeShort(), codegen=codegen)

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x0F, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x10, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                sink_ref,
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, h_field, codegen=codegen),
                    al_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "pseudo") is True

    _, _, third_stmt = codegen.cfunc.statements.statements
    assert isinstance(third_stmt, _decompile.structured_c.CAssignment)
    assert isinstance(third_stmt.rhs, _decompile.structured_c.CBinaryOp)
    assert third_stmt.rhs.op == "And"
    assert third_stmt.rhs.lhs.callee_target == "bios_int10_video"
    assert [arg.value for arg in third_stmt.rhs.lhs.args] == [0x0F]
    assert third_stmt.rhs.rhs.value == 0xFF


def test_interrupt_wrapper_result_lowering_rewrites_int10_cursor_shape_reads():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x3458, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"cx": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    sink = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="sink", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    x_field = _decompile.structured_c.CStructField(regs_struct, 0, "x", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    cx_field = _decompile.structured_c.CStructField(x_struct, 2, "cx", codegen=codegen)
    sink_ref = _decompile.structured_c.CVariable(sink.variable, variable_type=SimTypeShort(), codegen=codegen)

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x03, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x10, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                sink_ref,
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, x_field, codegen=codegen),
                    cx_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "pseudo") is True

    _, _, third_stmt = codegen.cfunc.statements.statements
    assert isinstance(third_stmt, _decompile.structured_c.CAssignment)
    assert isinstance(third_stmt.rhs, _decompile.structured_c.CFunctionCall)
    assert third_stmt.rhs.callee_target == "bios_int10_video"
    assert [arg.value for arg in third_stmt.rhs.args] == [0x03]


def test_interrupt_wrapper_result_lowering_rewrites_whole_outregs_reads():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x3459, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    regs_struct = SimStruct({"h": h_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    sink = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="sink", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    sink_ref = _decompile.structured_c.CVariable(sink.variable, variable_type=SimTypeShort(), codegen=codegen)

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x12, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x12, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(sink_ref, outregs, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "pseudo") is True

    _, _, third_stmt = codegen.cfunc.statements.statements
    assert isinstance(third_stmt, _decompile.structured_c.CAssignment)
    assert isinstance(third_stmt.rhs, _decompile.structured_c.CFunctionCall)
    assert third_stmt.rhs.callee_target == "bios_memsize"


def test_interrupt_wrapper_placeholder_calls_are_recovered_from_argument_shape(monkeypatch):
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x2345, statements=SimpleNamespace()),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    project = SimpleNamespace()
    callee_func = SimpleNamespace(name="CallReturn")
    call = _decompile.structured_c.CFunctionCall(
        "CallReturn",
        callee_func,
        [
            _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
            object(),
            object(),
            object(),
        ],
        codegen=codegen,
    )

    monkeypatch.setattr(_decompile, "_iter_c_nodes", lambda _node: [call])

    changed = _decompile._attach_interrupt_wrapper_callees(project, codegen, "pseudo")

    assert changed
    assert callee_func.name == "int86x"
    assert project._inertia_interrupt_wrappers[0x2345]["calls"][0].canonical_name == "int86x"


def test_interrupt_wrapper_callees_are_classified_and_canonicalized(monkeypatch):
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x1234, statements=SimpleNamespace()),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    project = SimpleNamespace()
    callee_func = SimpleNamespace(name="_int86x")
    call = _decompile.structured_c.CFunctionCall(
        "int86x",
        callee_func,
        [object(), object(), object(), object()],
        codegen=codegen,
    )

    monkeypatch.setattr(_decompile, "_iter_c_nodes", lambda _node: [call])

    changed = _decompile._attach_interrupt_wrapper_callees(project, codegen, "pseudo")

    assert changed
    assert callee_func.name == "int86x"
    cache_entry = project._inertia_interrupt_wrappers[0x1234]
    assert [item.canonical_name for item in cache_entry["calls"]] == ["int86x"]
    assert cache_entry["calls"][0].vector_arg is not None
    assert cache_entry["field_access_summary"] == {"input": [], "output": [], "segment": [], "other": []}


def test_interrupt_wrapper_field_paths_capture_regs_subfields():
    codegen = SimpleNamespace(
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"ax": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")
    base_var = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )
    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    first = _decompile.structured_c.CVariableField(base_var, h_field, codegen=codegen)
    second = _decompile.structured_c.CVariableField(first, ah_field, codegen=codegen)

    access = _decompile._interrupt_wrapper_field_path(second)
    assert access is not None
    assert access.base_name == "inregs"
    assert access.field_path == ("h", "ah")


def test_interrupt_wrapper_field_access_summary_groups_register_roles():
    accesses = [
        _decompile.InterruptWrapperFieldAccess("inregs", ("h", "ah"), object()),
        _decompile.InterruptWrapperFieldAccess("outregs", ("x", "bx"), object()),
        _decompile.InterruptWrapperFieldAccess("sregs", ("es",), object()),
    ]

    summary = _decompile._interrupt_wrapper_field_access_summary(accesses)

    assert [item.base_name for item in summary["input"]] == ["inregs"]
    assert [item.base_name for item in summary["output"]] == ["outregs"]
    assert [item.base_name for item in summary["segment"]] == ["sregs"]


def test_interrupt_wrapper_result_lowering_rewrites_known_output_reads():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x3456, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"ax": SimTypeShort(), "bx": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    sregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="sregs", region=0),
        variable_type=SimStruct({"es": SimTypeShort()}, name="SREGS"),
        codegen=codegen,
    )
    g_info = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(6, 2, base="bp", name="g_info", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    x_field = _decompile.structured_c.CStructField(regs_struct, 0, "x", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    ax_field = _decompile.structured_c.CStructField(x_struct, 0, "ax", codegen=codegen)
    bx_field = _decompile.structured_c.CStructField(x_struct, 2, "bx", codegen=codegen)
    es_field = _decompile.structured_c.CStructField(SimStruct({"es": SimTypeShort()}, name="SREGS"), 0, "es", codegen=codegen)

    g_info_ref = _decompile.structured_c.CVariable(g_info.variable, variable_type=SimTypeShort(), codegen=codegen)

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x30, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                g_info_ref,
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, x_field, codegen=codegen),
                    ax_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x35, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86x",
                    SimpleNamespace(name="int86x"),
                    [
                        _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    g_info_ref,
                    es_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CVariableField(sregs, es_field, codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    g_info_ref,
                    bx_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, x_field, codegen=codegen),
                    bx_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ]
        ,
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "modern") is True

    assignments = [stmt for stmt in codegen.cfunc.statements.statements if isinstance(stmt, _decompile.structured_c.CAssignment)]
    assert assignments[1].rhs.callee_target == "get_dos_version"
    assert assignments[3].rhs.callee_target == "FP_SEG"
    assert assignments[3].rhs.args[0].callee_target == "getvect"
    assert assignments[4].rhs.callee_target == "FP_OFF"
    assert assignments[4].rhs.args[0].callee_target == "getvect"


def test_interrupt_wrapper_result_lowering_keeps_byte_reads_byte_sized():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x3457, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    regs_struct = SimStruct({"h": h_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    sink = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="sink", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    al_field = _decompile.structured_c.CStructField(h_struct, 1, "al", codegen=codegen)

    sink_ref = _decompile.structured_c.CVariable(sink.variable, variable_type=SimTypeShort(), codegen=codegen)
    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x30, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(
                sink_ref,
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, h_field, codegen=codegen),
                    al_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "modern") is True

    _, _, third_stmt = codegen.cfunc.statements.statements
    assert isinstance(third_stmt, _decompile.structured_c.CAssignment)
    assert isinstance(third_stmt.rhs, _decompile.structured_c.CBinaryOp)
    assert third_stmt.rhs.op == "And"
    assert third_stmt.rhs.lhs.callee_target == "get_dos_version"
    assert third_stmt.rhs.rhs.value == 0xFF


def test_interrupt_wrapper_result_lowering_rewrites_wrapper_call_and_composite_ax_read():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4567, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"ax": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")

    inregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(0, 2, base="bp", name="inregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    g_info = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="g_info", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    h_field = _decompile.structured_c.CStructField(regs_struct, 0, "h", codegen=codegen)
    ah_field = _decompile.structured_c.CStructField(h_struct, 0, "ah", codegen=codegen)
    al_field = _decompile.structured_c.CStructField(h_struct, 1, "al", codegen=codegen)

    g_info_ref = _decompile.structured_c.CVariable(g_info.variable, variable_type=SimTypeShort(), codegen=codegen)

    ax_high = _decompile.structured_c.CBinaryOp(
        "Shl",
        _decompile.structured_c.CVariableField(
            _decompile.structured_c.CVariableField(outregs, h_field, codegen=codegen),
            ah_field,
            codegen=codegen,
        ),
        _decompile.structured_c.CConstant(8, SimTypeShort(), codegen=codegen),
        codegen=codegen,
    )
    ax_expr = _decompile.structured_c.CBinaryOp(
        "Or",
        ax_high,
        _decompile.structured_c.CVariableField(
            _decompile.structured_c.CVariableField(outregs, h_field, codegen=codegen),
            al_field,
            codegen=codegen,
        ),
        codegen=codegen,
    )

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CAssignment(
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(inregs, h_field, codegen=codegen),
                    ah_field,
                    codegen=codegen,
                ),
                _decompile.structured_c.CConstant(0x30, SimTypeShort(), codegen=codegen),
                codegen=codegen,
            ),
            _decompile.structured_c.CExpressionStatement(
                _decompile.structured_c.CFunctionCall(
                    "int86",
                    SimpleNamespace(name="int86"),
                    [
                        _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
                        object(),
                        object(),
                    ],
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
            _decompile.structured_c.CAssignment(g_info_ref, ax_expr, codegen=codegen),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "modern") is True

    _, second_stmt, third_stmt = codegen.cfunc.statements.statements
    assert isinstance(second_stmt, _decompile.structured_c.CExpressionStatement)
    assert second_stmt.expr.callee_target == "get_dos_version"
    assert isinstance(third_stmt, _decompile.structured_c.CAssignment)
    assert third_stmt.rhs.callee_target == "get_dos_version"


def test_interrupt_wrapper_result_lowering_falls_back_to_wrapper_call_when_service_name_is_unknown():
    codegen = SimpleNamespace(
        cfunc=SimpleNamespace(addr=0x4568, statements=None),
        project=SimpleNamespace(arch=_decompile.Arch86_16()),
        next_idx=lambda _name: 1,
        cstyle_null_cmp=False,
    )
    h_struct = SimStruct({"ah": SimTypeShort(), "al": SimTypeShort()}, name="REGS_H")
    x_struct = SimStruct({"ax": SimTypeShort()}, name="REGS_X")
    regs_struct = SimStruct({"h": h_struct, "x": x_struct}, name="REGS")

    outregs = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(2, 2, base="bp", name="outregs", region=0),
        variable_type=regs_struct,
        codegen=codegen,
    )
    g_info = _decompile.structured_c.CVariable(
        _decompile.SimStackVariable(4, 2, base="bp", name="g_info", region=0),
        variable_type=SimTypeShort(),
        codegen=codegen,
    )

    x_field = _decompile.structured_c.CStructField(regs_struct, 0, "x", codegen=codegen)
    ax_field = _decompile.structured_c.CStructField(x_struct, 0, "ax", codegen=codegen)
    g_info_ref = _decompile.structured_c.CVariable(g_info.variable, variable_type=SimTypeShort(), codegen=codegen)

    wrapper_call = _decompile.structured_c.CFunctionCall(
        "CallReturn",
        SimpleNamespace(name="CallReturn"),
        [
            _decompile.structured_c.CConstant(0x21, SimTypeShort(), codegen=codegen),
            object(),
            object(),
            object(),
        ],
        codegen=codegen,
    )

    stmts = _decompile.structured_c.CStatements(
        [
            _decompile.structured_c.CExpressionStatement(wrapper_call, codegen=codegen),
            _decompile.structured_c.CAssignment(
                g_info_ref,
                _decompile.structured_c.CVariableField(
                    _decompile.structured_c.CVariableField(outregs, x_field, codegen=codegen),
                    ax_field,
                    codegen=codegen,
                ),
                codegen=codegen,
            ),
        ],
        codegen=codegen,
    )
    codegen.cfunc.statements = stmts

    assert _decompile._lower_interrupt_wrapper_result_reads(SimpleNamespace(), codegen, "modern") is True

    first_stmt, second_stmt = codegen.cfunc.statements.statements
    assert isinstance(first_stmt, _decompile.structured_c.CExpressionStatement)
    assert first_stmt.expr.callee_target == "CallReturn"
    assert isinstance(second_stmt, _decompile.structured_c.CAssignment)
    assert isinstance(second_stmt.rhs, _decompile.structured_c.CFunctionCall)
    assert second_stmt.rhs.callee_target == "CallReturn"


def test_interrupt_helper_formatting_uses_helper_names(monkeypatch):
    call = _decompile.InterruptCall(insn_addr=0x1000, vector=0x12)
    helper_addr = _decompile.interrupt_service_addr(call)
    project = SimpleNamespace()
    function = SimpleNamespace(project=project)

    monkeypatch.setattr(_decompile, "collect_interrupt_service_calls", lambda _function, _binary_path=None: [call])
    monkeypatch.setattr(_decompile, "_helper_name", lambda _project, addr: "bios_int12_memory_size" if addr == helper_addr else None)

    replacements = _decompile._interrupt_call_replacement_map(project, function, "pseudo", None)
    declarations = _decompile._interrupt_helper_declarations(function, "pseudo", None)

    assert replacements["bios_int12_memory_size"] == "bios_memsize()"
    assert "int bios_memsize(void);" in declarations


def test_patch_interrupt_service_call_sites_handles_bios_vectors(monkeypatch):
    call = _decompile.InterruptCall(insn_addr=0x1234, vector=0x12)
    callee = SimpleNamespace(name="old_name", _init_prototype_and_calling_convention=lambda: None)
    project = SimpleNamespace(
        is_hooked=lambda _addr: False,
        hook=lambda _addr, _proc, replace=True: None,
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=True: callee if addr == 0xFE012 else None)),
    )
    function = SimpleNamespace(project=project, _call_sites={}, get_call_return=lambda _addr: 0x4321)

    monkeypatch.setitem(
        _decompile.patch_interrupt_service_call_sites.__globals__,
        "collect_interrupt_service_calls",
        lambda _function, _binary_path=None, vectors=None: [call],
    )
    monkeypatch.setitem(
        _decompile.patch_interrupt_service_call_sites.__globals__,
        "ensure_interrupt_service_hook",
        lambda _project, _call: (0xFE012, "bios_memsize"),
    )

    changed = _decompile.patch_interrupt_service_call_sites(function, None)

    assert changed
    assert function._call_sites[0x1234] == (0xFE012, 0x4321)
    assert callee.name == "bios_memsize"
