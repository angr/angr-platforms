from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.analysis_helpers import CallTargetSeed
from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616, summarize_x86_16_callsite


class _Operand:
    def __init__(self, *, reg: int | None = None, imm: int | None = None, size: int | None = None):
        self.reg = reg
        self.imm = imm
        self.size = size


class _Insn:
    def __init__(self, address: int, mnemonic: str, operands: list[_Operand] | None = None, reg_names: dict[int, str] | None = None):
        self.address = address
        self.mnemonic = mnemonic
        self.insn = SimpleNamespace(operands=tuple(operands or ()), reg_name=lambda reg: (reg_names or {}).get(reg, ""))


def _function_with_block(insns):
    block = SimpleNamespace(capstone=SimpleNamespace(insns=tuple(insns)))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    return SimpleNamespace(project=project)


def test_callsite_summary_reports_push_args_cleanup_and_return_use(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "push", [_Operand(imm=2, size=2)]),
            _Insn(0x1002, "call"),
            _Insn(0x1005, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
            _Insn(0x1008, "test", [_Operand(reg=2), _Operand(reg=2)], reg_names={2: "ax"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=0x1544,
        return_addr=0x1005,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register="ax",
        return_used=True,
        stack_probe_helper=False,
    )


def test_callsite_summary_returns_empty_shape_when_block_has_no_neighbors(monkeypatch):
    function = _function_with_block([_Insn(0x1002, "call")])
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1002,
        target_addr=None,
        return_addr=None,
        kind=None,
        arg_count=0,
        arg_widths=(),
        stack_cleanup=None,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_uses_containing_block_for_push_args_before_call(monkeypatch):
    insns = (
        _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
        _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
        _Insn(0x100E, "call"),
        _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_counts_pushes_separated_by_register_setup(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "push", [_Operand(imm=1, size=2)]),
            _Insn(0x1001, "mov", [_Operand(reg=2), _Operand(imm=0x61)], reg_names={2: "ax"}),
            _Insn(0x1004, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1005, "call"),
            _Insn(0x1008, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1005, 0x1544, 0x1008, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1005)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1005,
        target_addr=0x1544,
        return_addr=0x1008,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_counts_pushes_separated_by_register_arithmetic_chain(monkeypatch):
    function = _function_with_block(
        [
            _Insn(0x1000, "mov", [_Operand(reg=2), _Operand(imm=3)], reg_names={2: "ax"}),
            _Insn(0x1003, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x1005, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1008, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1009, "mov", [_Operand(reg=2), _Operand(imm=5)], reg_names={2: "ax"}),
            _Insn(0x100C, "shl", [_Operand(reg=2), _Operand(imm=1)], reg_names={2: "ax"}),
            _Insn(0x100E, "add", [_Operand(reg=2), _Operand(imm=0x0B4C)], reg_names={2: "ax"}),
            _Insn(0x1011, "push", [_Operand(reg=2, size=2)], reg_names={2: "ax"}),
            _Insn(0x1012, "call"),
            _Insn(0x1015, "add", [_Operand(reg=1), _Operand(imm=4)], reg_names={1: "sp"}),
        ]
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1012, 0x1544, 0x1015, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1012)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x1012,
        target_addr=0x1544,
        return_addr=0x1015,
        kind="direct_near",
        arg_count=2,
        arg_widths=(2, 2),
        stack_cleanup=4,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_uses_fallthrough_cleanup_block_after_call(monkeypatch):
    call_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1009, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
                _Insn(0x100A, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
                _Insn(0x100B, "push", [_Operand(imm=4, size=2)]),
                _Insn(0x100E, "call"),
            )
        )
    )
    cleanup_block = SimpleNamespace(
        capstone=SimpleNamespace(
            insns=(
                _Insn(0x1011, "add", [_Operand(reg=1), _Operand(imm=2)], reg_names={1: "sp"}),
            )
        )
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: call_block if addr == 0x1009 else cleanup_block),
    )
    function = SimpleNamespace(project=project, block_addrs_set={0x1009, 0x1011})
    monkeypatch.setattr(
        function,
        "get_call_sites",
        lambda: [0x100E],
        raising=False,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x100E, 0x1544, 0x1011, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x100E)

    assert summary == CallsiteSummary8616(
        callsite_addr=0x100E,
        target_addr=0x1544,
        return_addr=0x1011,
        kind="direct_near",
        arg_count=1,
        arg_widths=(2,),
        stack_cleanup=2,
        return_register=None,
        return_used=False,
        stack_probe_helper=False,
    )


def test_callsite_summary_marks_known_stack_probe_helpers(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_rebased_exact_slice_stack_probe_helper_from_original_project(monkeypatch):
    insns = (_Insn(0x1002, "call"),)
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    original_project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(addr=addr, name="aNchkstk") if addr == 0x11222 else None
            ),
            labels={0x11222: "aNchkstk"},
        ),
        _inertia_lst_metadata=SimpleNamespace(code_labels={0x11222: "aNchkstk"}),
    )
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        _inertia_original_project=original_project,
        _inertia_original_linear_delta=0x10222,
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1000, 0x1005, "direct_far")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_marks_stack_probe_returned_stack_address_when_ax_is_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "mov", [_Operand(reg=3), _Operand(reg=2)], reg_names={2: "ax", 3: "bx"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register == "ax"
    assert summary.return_used is True
    assert summary.helper_return_state == "stack_address"
    assert summary.helper_return_space == "ss"
    assert summary.helper_return_width == 2
    assert summary.helper_return_address_kind == "stack"


def test_callsite_summary_does_not_claim_stack_address_when_probe_return_is_not_consumed(monkeypatch):
    insns = (
        _Insn(0x1002, "call"),
        _Insn(0x1005, "push", [_Operand(reg=3, size=2)], reg_names={3: "di"}),
        _Insn(0x1006, "push", [_Operand(reg=4, size=2)], reg_names={4: "si"}),
    )
    block = SimpleNamespace(capstone=SimpleNamespace(insns=insns))
    callee = SimpleNamespace(addr=0x1544, name="aNchkstk")
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        factory=SimpleNamespace(block=lambda addr, opt_level=0: block),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: callee if addr == 0x1544 else None)),
    )
    function = SimpleNamespace(project=project)
    monkeypatch.setattr(
        "angr_platforms.X86_16.callsite_summary.collect_neighbor_call_targets",
        lambda _function: [CallTargetSeed(0x1002, 0x1544, 0x1005, "direct_near")],
    )

    summary = summarize_x86_16_callsite(function, 0x1002)

    assert summary is not None
    assert summary.stack_probe_helper is True
    assert summary.return_register is None
    assert summary.return_used is False
    assert summary.helper_return_state == "none"
    assert summary.helper_return_space is None
    assert summary.helper_return_width is None
    assert summary.helper_return_address_kind == "none"
