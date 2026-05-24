from angr_platforms.X86_16.analysis.stack_frame_ir import build_x86_16_ir_frame_access_artifact
from angr_platforms.X86_16.ir.core import AddressStatus, IRAddress, IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace


def test_ir_stack_frame_artifact_classifies_bp_args_and_locals():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                instrs=(
                    IRInstr("LOAD", IRValue(MemSpace.REG, name="ax", size=2), (IRAddress(MemSpace.SS, base=("bp",), offset=4, size=2, status=AddressStatus.PROVISIONAL),), size=2),
                    IRInstr("STORE", None, (IRAddress(MemSpace.SS, base=("bp",), offset=-2, size=2, status=AddressStatus.PROVISIONAL), IRValue(MemSpace.CONST, const=1)), size=2),
                ),
            ),
        ),
    )

    frame = build_x86_16_ir_frame_access_artifact(artifact)

    assert [(slot.offset, slot.role) for slot in frame.slots] == [(-2, "local"), (4, "arg")]
