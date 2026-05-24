from angr_platforms.X86_16.ir.core import (
    AddressStatus,
    IRAddress,
    IRBlock,
    IRCondition,
    IRFunctionArtifact,
    IRInstr,
    IRRefusal,
    IRValue,
    MemSpace,
    SegmentOrigin,
)


def test_ir_value_to_dict_preserves_expr_and_version():
    value = IRValue(space=MemSpace.REG, name="ax", size=2, version=1, expr=("phi",))

    assert value.to_dict() == {
        "kind": "value",
        "space": "reg",
        "name": "ax",
        "offset": 0,
        "const": None,
        "size": 2,
        "version": 1,
        "expr": ("phi",),
    }


def test_ir_address_to_dict_preserves_segment_base_and_status():
    addr = IRAddress(
        space=MemSpace.SS,
        base=("bp",),
        offset=-4,
        size=2,
        status=AddressStatus.PROVISIONAL,
        segment_origin=SegmentOrigin.DEFAULTED,
        expr=("Iop_Sub16", "bp"),
    )

    assert addr.to_dict() == {
        "kind": "address",
        "space": "ss",
        "base": ["bp"],
        "offset": -4,
        "size": 2,
        "status": "provisional",
        "segment_origin": "defaulted",
        "expr": ("Iop_Sub16", "bp"),
    }


def test_ir_condition_to_dict_keeps_typed_args():
    cond = IRCondition(
        op="eq",
        args=(IRValue(MemSpace.REG, name="ax", size=2), IRValue(MemSpace.REG, name="bx", size=2)),
        expr=("Iop_CmpEQ16",),
    )

    rendered = cond.to_dict()

    assert rendered["kind"] == "condition"
    assert rendered["op"] == "eq"
    assert rendered["args"][0]["name"] == "ax"
    assert rendered["expr"] == ("Iop_CmpEQ16",)


def test_ir_function_artifact_to_dict_keeps_summary_and_refusals():
    artifact = IRFunctionArtifact(
        function_addr=0x4010,
        blocks=(
            IRBlock(
                addr=0x4010,
                successor_addrs=(0x4020,),
                instrs=(
                    IRInstr(
                        op="LOAD",
                        dst=IRValue(MemSpace.TMP, name="t0", size=2),
                        args=(
                            IRAddress(
                                MemSpace.DS,
                                base=("si",),
                                offset=0,
                                size=2,
                                status=AddressStatus.PROVISIONAL,
                                segment_origin=SegmentOrigin.DEFAULTED,
                            ),
                        ),
                    ),
                ),
            ),
        ),
        refusals=(IRRefusal("unsupported_stmt", "Ist_Dirty", 0x4010),),
        summary={"block_count": 1, "address_status_counts": {"provisional": 1}, "segment_origin_counts": {"defaulted": 1}},
    )

    rendered = artifact.to_dict()

    assert rendered["function_addr"] == 0x4010
    assert rendered["summary"]["address_status_counts"] == {"provisional": 1}
    assert rendered["summary"]["segment_origin_counts"] == {"defaulted": 1}
    assert rendered["refusals"][0]["kind"] == "unsupported_stmt"
    assert rendered["blocks"][0]["successor_addrs"] == [0x4020]
