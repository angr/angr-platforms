from angr_platforms.X86_16.ir.core import IRBlock, IRFunctionArtifact, IRInstr, IRValue, MemSpace
from angr_platforms.X86_16.ir.ssa import build_x86_16_block_local_ssa
from angr_platforms.X86_16.ir.ssa_function import build_x86_16_function_ssa


def test_block_local_ssa_versions_register_defs_monotonically():
    block = IRBlock(
        addr=0x1000,
        instrs=(
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=1),), size=2),
            IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.REG, name="ax", size=2),), size=2),
        ),
    )

    ssa = build_x86_16_block_local_ssa(block)

    assert [binding.version for binding in ssa.bindings] == [0, 1]
    assert ssa.instrs[1].args[0].version == 0
    assert ssa.instrs[1].dst.version == 1


def test_function_ssa_builds_phi_node_at_cfg_join():
    artifact = IRFunctionArtifact(
        function_addr=0x1000,
        blocks=(
            IRBlock(
                addr=0x1000,
                successor_addrs=(0x1020, 0x1010),
                instrs=(IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=1),), size=2),),
            ),
            IRBlock(
                addr=0x1010,
                successor_addrs=(0x1020,),
                instrs=(IRInstr("MOV", IRValue(MemSpace.REG, name="ax", size=2), (IRValue(MemSpace.CONST, const=2),), size=2),),
            ),
            IRBlock(addr=0x1020, instrs=()),
        ),
    )

    function_ssa = build_x86_16_function_ssa(artifact)

    assert function_ssa.summary["phi_node_count"] == 1
    assert function_ssa.predecessor_map[0x1020] == (0x1000, 0x1010)
    phi = function_ssa.phi_nodes[0]
    assert phi.block_addr == 0x1020
    assert phi.target.name == "ax"
    assert [item.source_block_addr for item in phi.incoming] == [0x1000, 0x1010]
