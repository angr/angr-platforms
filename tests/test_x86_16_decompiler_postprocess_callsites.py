from __future__ import annotations

from types import SimpleNamespace

from angr.analyses.decompiler.structured_codegen.c import CFunctionCall, CStatements

from angr_platforms.X86_16.analysis_helpers import collect_neighbor_call_targets, resolve_direct_call_target_from_block
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.decompiler_postprocess_calls import (
    _attach_callsite_summaries_8616,
    _lookup_callee_function_8616,
    _normalize_call_target_names_8616,
)
from angr_platforms.X86_16.pipeline.errors import PipelineHardError


class _DummyCodegen:
    def __init__(self, project):
        self._idx = 0
        self.project = project
        self.cstyle_null_cmp = False

    def next_idx(self, _name: str) -> int:
        self._idx += 1
        return self._idx


def test_attach_callsite_summaries_sets_summary_and_binds_callee(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee = SimpleNamespace(name="::0x1544::InitBars")
    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else (callee if addr == 0x1544 else None)
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_summaries[id(call)] == CallsiteSummary8616(
        callsite_addr=0x4012,
        target_addr=0x1544,
        return_addr=0x4015,
        kind="direct_near",
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
    )
    assert call.callee_func is callee
    assert call.callee_target == "InitBars"


def test_attach_callsite_summaries_recovers_empty_direct_callsite_inventory_from_blocks(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x4012
            self.mnemonic = "call"
            self.size = 3
            self.insn = SimpleNamespace(operands=( _Operand(2, 0x1544), ), size=3)

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)), size=3)
    project.factory = SimpleNamespace(block=lambda addr, opt_level=0: block)

    callee = SimpleNamespace(name="::0x1544::InitBars")
    function = SimpleNamespace(
        addr=0x4010,
        project=project,
        block_addrs_set={0x4012},
        _call_sites={},
        get_call_sites=lambda: tuple(sorted(function._call_sites)),
        get_call_target=lambda callsite: function._call_sites[callsite][0],
        get_call_return=lambda callsite: function._call_sites[callsite][1],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: function if addr == 0x4010 else (callee if addr == 0x1544 else None)
        )
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert function.get_call_sites() == (0x4012,)
    assert call.callee_func is callee
    assert call.callee_target == "InitBars"


def test_attach_callsite_summaries_prefers_call_tags_over_ast_zip_order(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    first = CFunctionCall(None, None, [], tags={"ins_addr": 0x4015}, codegen=codegen)
    second = CFunctionCall(None, None, [], tags={"ins_addr": 0x4012}, codegen=codegen)
    root = CStatements([first, second], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    callee_a = SimpleNamespace(name="::0x1544::InitBars")
    callee_b = SimpleNamespace(name="::0x1666::DrawTime")
    function = SimpleNamespace(
        addr=0x4010,
        get_call_sites=lambda: [0x4012, 0x4015],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else callee_a if addr == 0x1544 else callee_b if addr == 0x1666 else None
            )
        )
    )

    def _fake_summary(_function, callsite_addr):
        if callsite_addr == 0x4012:
            return CallsiteSummary8616(0x4012, 0x1544, 0x4015, "direct_near", 0, (), None, None, False)
        return CallsiteSummary8616(0x4015, 0x1666, 0x4018, "direct_near", 0, (), None, None, False)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _fake_summary,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert second.callee_func is callee_a
    assert second.callee_target == "InitBars"
    assert first.callee_func is callee_b
    assert first.callee_target == "DrawTime"


def test_resolve_direct_call_target_rebases_exact_slice_linear_target():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x100E
            self.mnemonic = "call"
            self.insn = SimpleNamespace(operands=(_Operand(2, 0x0F60),))

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)))
    slice_project = SimpleNamespace(
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x2B)),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )

    assert resolve_direct_call_target_from_block(slice_project, 0x100E) == 0x106C8


def test_collect_neighbor_call_targets_keeps_rebased_exact_slice_direct_calls():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self):
            self.address = 0x100E
            self.mnemonic = "call"
            self.size = 3
            self.insn = SimpleNamespace(operands=(_Operand(2, 0x0F60),), size=3)

    block = SimpleNamespace(capstone=SimpleNamespace(insns=(_Insn(),)), size=3)
    slice_project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x1000, max_addr=0x2B)),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )
    function = SimpleNamespace(
        project=slice_project,
        get_call_sites=lambda: (0x100E,),
        get_call_target=lambda callsite: None,
        get_call_return=lambda callsite: 0x1011,
        block_addrs_set={0x1009},
    )

    recovered = collect_neighbor_call_targets(function)

    assert len(recovered) == 1
    assert recovered[0].callsite_addr == 0x100E
    assert recovered[0].target_addr == 0x106C8
    assert recovered[0].kind == "direct_far"


def test_resolve_direct_call_target_from_block_uses_exact_mid_block_callsite_address():
    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands, size=3):
            self.address = address
            self.mnemonic = mnemonic
            self.size = size
            self.insn = SimpleNamespace(operands=tuple(operands), size=size)

    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1000, "mov", []),
                _Insn(0x1003, "call", [_Operand(2, 0x0F60)]),
                _Insn(0x1006, "add", []),
            )
        )
    )
    slice_project = SimpleNamespace(
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=SimpleNamespace(
            loader=SimpleNamespace(main_object=SimpleNamespace(linked_base=0x10000, max_addr=0xAC37))
        ),
        _inertia_original_linear_delta=0xF768,
    )

    assert resolve_direct_call_target_from_block(slice_project, 0x1003) == 0x106C8


def test_attach_callsite_summaries_recovers_multiple_mid_block_direct_calls(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    codegen = _DummyCodegen(project)
    first = CFunctionCall(None, None, [], tags={"ins_addr": 0x4013}, codegen=codegen)
    second = CFunctionCall(None, None, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([first, second], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    class _Operand:
        def __init__(self, type_, imm):
            self.type = type_
            self.imm = imm

    class _Insn:
        def __init__(self, address, mnemonic, operands, size=3):
            self.address = address
            self.mnemonic = mnemonic
            self.size = size
            self.insn = SimpleNamespace(operands=tuple(operands), size=size)

    block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x4010, "push", []),
                _Insn(0x4013, "call", [_Operand(2, 0x1544)]),
                _Insn(0x4016, "add", []),
                _Insn(0x4018, "call", [_Operand(2, 0x1666)]),
                _Insn(0x401B, "add", []),
            )
        ),
        size=0x0E,
    )
    project.factory = SimpleNamespace(block=lambda addr, opt_level=0: block)

    callee_a = SimpleNamespace(name="::0x1544::InitBars")
    callee_b = SimpleNamespace(name="::0x1666::DrawTime")
    function = SimpleNamespace(
        addr=0x4010,
        project=project,
        block_addrs_set={0x4010},
        _call_sites={},
        get_call_sites=lambda: tuple(sorted(function._call_sites)),
        get_call_target=lambda callsite: function._call_sites[callsite][0],
        get_call_return=lambda callsite: function._call_sites[callsite][1],
    )
    project.kb = SimpleNamespace(
        functions=SimpleNamespace(
            function=lambda addr, create=False: (
                function if addr == 0x4010 else callee_a if addr == 0x1544 else callee_b if addr == 0x1666 else None
            )
        )
    )

    def _fake_summary(_function, callsite_addr):
        if callsite_addr == 0x4013:
            return CallsiteSummary8616(0x4013, 0x1544, 0x4016, "direct_near", 0, (), None, None, False)
        return CallsiteSummary8616(0x4018, 0x1666, 0x401B, "direct_near", 0, (), None, None, False)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        _fake_summary,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert function.get_call_sites() == (0x4013, 0x4018)
    assert first.callee_func is callee_a
    assert first.callee_target == "InitBars"
    assert second.callee_func is callee_b
    assert second.callee_target == "DrawTime"


def test_attach_callsite_summaries_binds_original_project_callee_for_rebased_exact_slice(monkeypatch):
    project = SimpleNamespace(
        _inertia_original_project=SimpleNamespace(
            kb=SimpleNamespace(
                functions=SimpleNamespace(
                    function=lambda addr, create=False: SimpleNamespace(addr=addr, name="DrawBar") if addr == 0x106C8 else None
                )
            )
        ),
        _inertia_original_linear_delta=0xF768,
    )
    codegen = _DummyCodegen(project)
    call = CFunctionCall(None, None, [], tags={"ins_addr": 0x100E}, codegen=codegen)
    root = CStatements([call], addr=0x1000, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x1000, statements=root, body=root)

    function = SimpleNamespace(addr=0x1000, get_call_sites=lambda: [0x100E])
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x1000 else None))
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x106C8,
            return_addr=0x1011,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is not None
    assert call.callee_func.name == "DrawBar"
    assert call.callee_target == "DrawBar"


def test_attach_callsite_summaries_replaces_conflicting_empty_stub_name_with_sidecar_label(monkeypatch):
    target = SimpleNamespace(addr=0x1666, name="DrawBar", block_addrs_set=())
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: function if addr == 0x4010 else (target if addr == 0x1666 else None)
            )
        )
    )
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawBar", target, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4018])

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x1666,
            return_addr=0x401B,
            kind="direct_near",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, target_addr: "DrawTime" if target_addr == 0x1666 else None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is target
    assert call.callee_func.name == "DrawTime"
    assert call.callee_target == "DrawTime"


def test_attach_callsite_summaries_uses_cod_source_call_order_for_repeated_non_probe_calls(monkeypatch):
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    probe = CFunctionCall("aNchkstk", SimpleNamespace(addr=0x1222, name="aNchkstk", block_addrs_set=()), [], codegen=codegen)
    draw_a = CFunctionCall("DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set=()), [], codegen=codegen)
    draw_b = CFunctionCall("DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set=()), [], codegen=codegen)
    draw_c = CFunctionCall("DrawBar", SimpleNamespace(addr=0x1666, name="DrawBar", block_addrs_set=()), [], codegen=codegen)
    root = CStatements([probe, draw_a, draw_b, draw_c], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4012, 0x4015, 0x4018, 0x401B])
    project.kb = SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == 0x4010 else None))

    summaries = {
        0x4012: CallsiteSummary8616(0x4012, 0x1222, 0x4015, "direct_far", 0, (), None, None, False, True),
        0x4015: CallsiteSummary8616(0x4015, 0x1544, 0x4018, "direct_far", 1, (2,), 2, "ax", True),
        0x4018: CallsiteSummary8616(0x4018, 0x1544, 0x401B, "direct_far", 1, (2,), 2, "ax", True),
        0x401B: CallsiteSummary8616(0x401B, 0x1666, 0x401E, "direct_far", 1, (2,), 2, "ax", True),
    }
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, callsite_addr: summaries[callsite_addr],
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(
            call_sources=(
                ("DrawBar", "DrawBar(iRow1)"),
                ("DrawBar", "DrawBar(iRow2)"),
                ("DrawTime", "DrawTime(iRow1)"),
            )
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert draw_a.callee_target == "DrawBar"
    assert draw_b.callee_target == "DrawBar"
    assert draw_c.callee_target == "DrawTime"
    assert draw_c.callee_func.name == "DrawTime"


def test_attach_callsite_summaries_rebinds_non_entry_direct_target_to_containing_function(monkeypatch):
    drawtime = SimpleNamespace(addr=0x1666, name="DrawTime", block_addrs_set={0x1666})
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    function = SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x4018])

    class _Functions:
        def function(self, addr=None, create=False):
            if addr == 0x4010:
                return function
            if addr == 0x1544:
                return stale
            return None

        def floor_func(self, addr):
            if 0x1666 <= addr < 0x1700:
                return drawtime
            return None

        def ceiling_addr(self, addr):
            if addr < 0x1700:
                return 0x1700
            return None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x4018}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr: CallsiteSummary8616(
            callsite_addr=0x4018,
            target_addr=0x166b,
            return_addr=0x401B,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is drawtime


def test_attach_callsite_summaries_drops_stale_mismatched_callee_when_source_call_order_identifies_target(monkeypatch):
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x401B])
                if addr == 0x4010
                else None
            )
        )
    )
    codegen = _DummyCodegen(project)
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x401B}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr: CallsiteSummary8616(
            callsite_addr=0x401B,
            target_addr=0x166B,
            return_addr=0x401E,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_sources=(("DrawTime", "DrawTime(iRow1)"),)),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._lookup_callee_function_8616",
        lambda _project, _target_addr: None,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert call.callee_func is None
    assert call.callee_target == "DrawTime"


def test_lookup_callee_function_rejects_mismatched_exact_lookup_and_uses_containing_function():
    drawbar = SimpleNamespace(addr=0x1F60, name="DrawBar", block_addrs_set={0x1F60})
    drawtime = SimpleNamespace(addr=0x1048B, name="DrawTime", block_addrs_set={0x1048B, 0x10491})

    class _Functions:
        def function(self, addr=None, create=False):
            if addr == 0x10491:
                return drawbar
            return None

        def floor_func(self, addr):
            if 0x1048B <= addr < 0x10498:
                return drawtime
            return None

        def ceiling_addr(self, addr):
            if addr <= 0x10498:
                return 0x10498
            return None

    project = SimpleNamespace(kb=SimpleNamespace(functions=_Functions()))

    resolved = _lookup_callee_function_8616(project, 0x10491)

    assert resolved is drawtime


def test_callsite_stats_reject_known_prototype_arg_mismatch():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall("DrawBar", SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544}), [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        )
    }

    try:
        _normalize_call_target_names_8616(codegen)
    except PipelineHardError as ex:
        assert "known prototype call argument mismatch" in str(ex)
    else:
        raise AssertionError("expected PipelineHardError")

    stats = codegen._inertia_callsite_materialization_stats
    assert stats.known_prototype_arg_mismatch_count == 1
    assert stats.failure_count >= 1


def test_callsite_stats_ignore_summary_arg_facts_for_known_zero_arg_helper():
    project = SimpleNamespace()
    codegen = _DummyCodegen(project)
    call = CFunctionCall("clock", SimpleNamespace(addr=0x1544, name="clock", block_addrs_set={0x1544}), [], codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)
    codegen._inertia_callsite_summaries = {
        id(call): CallsiteSummary8616(
            callsite_addr=0x4012,
            target_addr=0x1544,
            return_addr=0x4015,
            kind="direct_near",
            arg_count=2,
            arg_widths=(2, 2),
            stack_cleanup=4,
            return_register=None,
            return_used=False,
        )
    }

    changed = _normalize_call_target_names_8616(codegen)
    stats = codegen._inertia_callsite_materialization_stats

    assert changed is False
    assert stats.call_arg_fact_count == 0
    assert stats.call_arg_materialized_count == 0
    assert stats.known_prototype_arg_mismatch_count == 0
    assert stats.failure_count == 0


def test_callsite_stats_count_stale_target_rejection(monkeypatch):
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(addr=0x4010, get_call_sites=lambda: [0x401B])
                if addr == 0x4010
                else None
            )
        )
    )
    codegen = _DummyCodegen(project)
    stale = SimpleNamespace(addr=0x1544, name="DrawBar", block_addrs_set={0x1544})
    call = CFunctionCall("DrawBar", stale, [], tags={"ins_addr": 0x401B}, codegen=codegen)
    root = CStatements([call], addr=0x4010, codegen=codegen)
    codegen.cfunc = SimpleNamespace(addr=0x4010, statements=root, body=root)

    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls.summarize_x86_16_callsite",
        lambda _function, _callsite_addr: CallsiteSummary8616(
            callsite_addr=0x401B,
            target_addr=0x166B,
            return_addr=0x401E,
            kind="direct_near",
            arg_count=1,
            arg_widths=(2,),
            stack_cleanup=2,
            return_register=None,
            return_used=False,
        ),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._cod_metadata_for_function_8616",
        lambda _project, _addr: SimpleNamespace(call_sources=(("DrawTime", "DrawTime(iRow1)"),)),
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._sidecar_label_for_target_8616",
        lambda _project, _target_addr: None,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.decompiler_postprocess_calls._lookup_callee_function_8616",
        lambda _project, _target_addr: stale,
    )

    changed = _attach_callsite_summaries_8616(project, codegen)

    assert changed is True
    assert codegen._inertia_callsite_materialization_stats.stale_target_rejected_count == 1
