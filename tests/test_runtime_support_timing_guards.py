from __future__ import annotations

import angr_platforms.X86_16.lowering.stack_lowering_from_facts as stack_lowering_from_facts

from inertia_decompiler.runtime_support import guard_angr_structuring_codegen_internal_timing


def test_guard_structuring_timing_preserves_stack_lowering_from_facts_signature(monkeypatch):
    recorded: list[tuple[object, tuple[object, ...], dict[str, object]]] = []

    def _fake_lower_stack_accesses_from_alias_facts_8616(codegen, alias_facts, **kwargs):
        recorded.append((codegen, (alias_facts,), kwargs))
        return "ok"

    monkeypatch.setattr(
        stack_lowering_from_facts,
        "lower_stack_accesses_from_alias_facts_8616",
        _fake_lower_stack_accesses_from_alias_facts_8616,
    )

    with guard_angr_structuring_codegen_internal_timing():
        result = stack_lowering_from_facts.lower_stack_accesses_from_alias_facts_8616(
            "cg",
            ["fact"],
            validation_clone=True,
        )

    assert result == "ok"
    assert recorded == [("cg", (["fact"],), {"validation_clone": True})]
