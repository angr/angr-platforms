from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.ir.condition_ir import ConditionIR
from angr_platforms.X86_16.lowering.condition_transfer import collect_typed_conditions_from_emulator_8616


def test_collect_typed_conditions_relifts_blocks_when_cache_is_empty(monkeypatch):
    from angr_platforms.X86_16.lift_86_16 import Instruction_ANY

    original_cache = getattr(Instruction_ANY, "_inertia_module_condition_cache", {})
    condition = ConditionIR("sgt", "ax", "bx")
    lifted_blocks: list[int] = []

    def _lift_block(block_addr: int, opt_level: int = 0):
        lifted_blocks.append(block_addr)
        Instruction_ANY._inertia_module_condition_cache[block_addr] = [condition]
        return None

    Instruction_ANY._inertia_module_condition_cache = {}
    project = SimpleNamespace(
        kb=SimpleNamespace(
            functions=SimpleNamespace(
                function=lambda addr, create=False: SimpleNamespace(block_addrs_set={addr, addr + 4})
            )
        ),
        factory=SimpleNamespace(block=_lift_block),
    )

    try:
        conditions = collect_typed_conditions_from_emulator_8616(project, 0x4010)
    finally:
        Instruction_ANY._inertia_module_condition_cache = original_cache

    assert lifted_blocks == [0x4010, 0x4014]
    assert conditions == [condition]
