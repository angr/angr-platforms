from __future__ import annotations

from types import SimpleNamespace

import pytest

from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRCondition, MemSpace, SegmentOrigin
from angr_platforms.X86_16.ir.vex_import import (
    apply_x86_16_vex_ir_artifact,
    build_x86_16_ir_function_artifact,
)


def _const(value: int):
    return SimpleNamespace(tag="Iex_Const", con=SimpleNamespace(value=value))


def _get(offset: int):
    return SimpleNamespace(tag="Iex_Get", offset=offset)


def _rdtmp(tmp: int):
    return SimpleNamespace(tag="Iex_RdTmp", tmp=tmp)


def _binop(op: str, *args):
    return SimpleNamespace(tag="Iex_Binop", op=op, args=args)


def _wrtmp(tmp: int, data):
    return SimpleNamespace(tag="Ist_WrTmp", tmp=tmp, data=data)


def _store(addr, data):
    return SimpleNamespace(tag="Ist_Store", addr=addr, data=data)


def _exit(guard, dst):
    return SimpleNamespace(tag="Ist_Exit", guard=guard, dst=dst)


def _ite(cond, iftrue, iffalse):
    return SimpleNamespace(tag="Iex_ITE", cond=cond, iftrue=iftrue, iffalse=iffalse)


def _flag_test(mask: int, *, is_set: bool):
    return _binop(
        "Iop_CmpNE8" if is_set else "Iop_CmpEQ8",
        _binop("Iop_And16", _get(18), _const(mask)),
        _const(0),
    )


def _flags_equal(mask_a: int, mask_b: int):
    return _binop("Iop_CmpEQ8", _flag_test(mask_a, is_set=True), _flag_test(mask_b, is_set=True))


def _flags_not_equal(mask_a: int, mask_b: int):
    return _binop("Iop_CmpNE8", _flag_test(mask_a, is_set=True), _flag_test(mask_b, is_set=True))


def _insn(mnemonic: str, op_str: str = ""):
    return SimpleNamespace(mnemonic=mnemonic, op_str=op_str)


def _block(addr: int, *stmts, next_expr=None, insns=()):
    return SimpleNamespace(
        addr=addr,
        vex=SimpleNamespace(statements=stmts, next=next_expr),
        capstone=SimpleNamespace(insns=tuple(insns)),
    )


class _FakeFactory:
    def __init__(self, blocks):
        self._blocks = blocks

    def block(self, addr, opt_level=0):  # noqa: ARG002
        return self._blocks[addr]


def _project(blocks, function):
    return SimpleNamespace(
        factory=_FakeFactory(blocks),
        kb=SimpleNamespace(functions=SimpleNamespace(function=lambda addr, create=False: function if addr == function.addr else None)),
    )


def test_vex_import_maps_si_based_store_to_typed_provisional_ds_address():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(12)),
                _wrtmp(1, _const(4)),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(0x55)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert store.op == "STORE"
    assert store.dst is None
    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.DS
    assert addr.base == ("si",)
    assert addr.offset == 4
    assert addr.status == AddressStatus.PROVISIONAL
    assert addr.segment_origin == SegmentOrigin.DEFAULTED


def test_vex_import_keeps_load_arguments_typed_as_address():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(12)),
                _wrtmp(1, SimpleNamespace(tag="Iex_Load", addr=_rdtmp(0), result_size=2)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    load = artifact.blocks[0].instrs[-1]

    assert load.op == "LOAD"
    assert isinstance(load.args[0], IRAddress)
    assert load.args[0].base == ("si",)


def test_vex_import_maps_bp_sub_offset_to_proven_ss_frame_slot():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(10)),
                _wrtmp(1, _const(6)),
                _wrtmp(2, _binop("Iop_Sub16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(1)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    store = artifact.blocks[0].instrs[-1]
    addr = store.args[0]

    assert isinstance(addr, IRAddress)
    assert addr.space == MemSpace.SS
    assert addr.base == ("bp",)
    assert addr.offset == -6
    assert addr.status == AddressStatus.STABLE
    assert addr.segment_origin == SegmentOrigin.PROVEN
    assert artifact.summary["frame_slot_count"] == 1
    assert artifact.summary["address_status_counts"]["stable"] >= 1
    assert artifact.summary["segment_origin_counts"]["proven"] >= 1


def test_vex_import_keeps_register_pair_address_tuple_for_alias():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(6)),
                _wrtmp(1, _get(12)),
                _wrtmp(2, _binop("Iop_Add16", _rdtmp(0), _rdtmp(1))),
                _store(_rdtmp(2), _const(0x33)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.base == ("bx", "si")
    assert addr.space == MemSpace.DS
    assert addr.segment_origin == SegmentOrigin.DEFAULTED


def test_vex_import_marks_string_destination_di_as_proven_es():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(14)),
                _store(_rdtmp(0), _const(0x33)),
                insns=(_insn("rep movsb"),),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    addr = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(addr, IRAddress)
    assert addr.base == ("di",)
    assert addr.space == MemSpace.ES
    assert addr.status == AddressStatus.STABLE
    assert addr.segment_origin == SegmentOrigin.PROVEN


def test_vex_import_lifts_comparison_exit_to_typed_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(0)),
                _wrtmp(1, _get(6)),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "eq"
    assert [value.name for value in cond.args] == ["ax", "bx"]
    assert artifact.summary["condition_counts"] == {"eq": 1}


def test_vex_import_folds_compare_with_zero_to_nonzero_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(12)),
                _wrtmp(1, _binop("Iop_CmpNE16", _rdtmp(0), _const(0))),
                _exit(_rdtmp(1), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "nonzero"
    assert [value.name for value in cond.args] == ["si"]


def test_vex_import_lifts_unsigned_compare_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(0)),
                _wrtmp(1, _get(6)),
                _wrtmp(2, _binop("Iop_CmpLT16U", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "ult"
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_lifts_masked_nonzero_exit_to_typed_condition():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(12)),
                _wrtmp(1, _const(1)),
                _wrtmp(2, _binop("Iop_And16", _rdtmp(0), _rdtmp(1))),
                _exit(_rdtmp(2), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cjmp = artifact.blocks[0].instrs[-1]
    cond = cjmp.args[0]

    assert cjmp.op == "CJMP"
    assert isinstance(cond, IRCondition)
    assert cond.op == "masked_nonzero"
    assert [value.name for value in cond.args] == ["si", None]
    assert artifact.summary["condition_counts"] == {"masked_nonzero": 1}


def test_vex_import_preserves_ite_wrapped_condition_temp_for_exit():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(12)),
                _wrtmp(1, _const(0)),
                _wrtmp(2, _binop("Iop_CmpNE16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, _ite(_rdtmp(2), _const(0), _const(1))),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "zero"
    assert [value.name for value in cond.args] == ["si"]


@pytest.mark.parametrize(
    ("guard_expr", "expected_op"),
    [
        (_flag_test(0x0040, is_set=True), "eq"),
        (_flag_test(0x0040, is_set=False), "ne"),
        (_flag_test(0x0001, is_set=True), "ult"),
        (_flag_test(0x0001, is_set=False), "uge"),
        (_binop("Iop_Or8", _flag_test(0x0001, is_set=True), _flag_test(0x0040, is_set=True)), "ule"),
        (_binop("Iop_And8", _flag_test(0x0001, is_set=False), _flag_test(0x0040, is_set=False)), "ugt"),
        (_flags_not_equal(0x0080, 0x0800), "slt"),
        (_flags_equal(0x0080, 0x0800), "sge"),
        (_binop("Iop_Or8", _flag_test(0x0040, is_set=True), _flags_not_equal(0x0080, 0x0800)), "sle"),
        (_binop("Iop_And8", _flag_test(0x0040, is_set=False), _flags_equal(0x0080, 0x0800)), "sgt"),
    ],
)
def test_vex_import_lifts_flag_formula_jcc_variants_to_typed_compare(guard_expr, expected_op):
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(0)),
                _wrtmp(1, _get(6)),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, guard_expr),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == expected_op
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_inverts_ite_wrapped_flag_formula_to_complement_compare():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    sgt_formula = _binop("Iop_And8", _flag_test(0x0040, is_set=False), _flags_equal(0x0080, 0x0800))
    project = _project(
        {
            0x1000: _block(
                0x1000,
                _wrtmp(0, _get(0)),
                _wrtmp(1, _get(6)),
                _wrtmp(2, _binop("Iop_CmpEQ16", _rdtmp(0), _rdtmp(1))),
                _wrtmp(3, _ite(sgt_formula, _const(0), _const(1))),
                _exit(_rdtmp(3), _const(0x1010)),
            )
        },
        function,
    )

    artifact = build_x86_16_ir_function_artifact(project, function)
    cond = artifact.blocks[0].instrs[-1].args[0]

    assert isinstance(cond, IRCondition)
    assert cond.op == "sle"
    assert [value.name for value in cond.args] == ["ax", "bx"]


def test_vex_import_records_successor_addrs_and_function_ssa():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000, 0x1010, 0x1020}, info={})
    project = _project(
        {
            0x1000: _block(0x1000, _wrtmp(0, _get(0)), next_expr=_const(0x1010)),
            0x1010: _block(0x1010, _wrtmp(0, _get(0)), next_expr=_const(0x1020)),
            0x1020: _block(0x1020, _wrtmp(0, _get(0))),
        },
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_artifact.blocks[0].successor_addrs == (0x1010,)
    assert codegen._inertia_vex_ir_function_ssa.summary["block_count"] == 3
    assert function.info["x86_16_vex_ir_function_ssa"]["summary"]["block_count"] == 3


def test_apply_vex_ir_artifact_attaches_summary_to_codegen_and_function_info():
    function = SimpleNamespace(addr=0x1000, block_addrs_set={0x1000}, info={})
    project = _project(
        {0x1000: _block(0x1000, _wrtmp(0, _get(14)), _store(_rdtmp(0), _const(2)))},
        function,
    )
    codegen = SimpleNamespace(cfunc=SimpleNamespace(addr=0x1000))

    changed = apply_x86_16_vex_ir_artifact(project, codegen)

    assert changed is False
    assert codegen._inertia_vex_ir_summary["instruction_count"] == 2
    assert function.info["x86_16_vex_ir_summary"]["instruction_count"] == 2
    assert "x86_16_vex_ir_function_ssa" in function.info
