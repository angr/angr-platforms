from __future__ import annotations

from types import SimpleNamespace

from angr_platforms.X86_16.callsite_summary import CallsiteSummary8616
from angr_platforms.X86_16.function_summary import FunctionSummary8616, summarize_x86_16_function


def test_function_summary_collects_callsite_and_typed_ir_kinds(monkeypatch):
    project = SimpleNamespace(arch=SimpleNamespace(name="86_16"))
    function = SimpleNamespace(
        addr=0x4010,
        info={
            "x86_16_vex_ir_summary": {
                "condition_counts": {"compare": 2, "masked_nonzero": 1},
                "register_clobbers": {"ds": 1, "cf": 1},
                "address_space_counts": {"ss": 3, "ds": 1, "reg": 0},
                "stable_address_space_counts": {"ss": 2, "ds": 0},
                "frame_slot_count": 3,
            }
        },
        get_call_sites=lambda: [0x4012, 0x4018],
        project=project,
    )
    monkeypatch.setattr(
        "angr_platforms.X86_16.function_summary.summarize_x86_16_callsite",
        lambda _function, callsite_addr: CallsiteSummary8616(
            callsite_addr=callsite_addr,
            target_addr=0x5000 + callsite_addr,
            return_addr=callsite_addr + 3,
            kind="direct_near" if callsite_addr == 0x4012 else "direct_far",
            arg_count=0,
            arg_widths=(),
            stack_cleanup=None,
            return_register=None,
            return_used=False,
        ),
    )

    summary = summarize_x86_16_function(project, function)

    assert summary == FunctionSummary8616(
        function_addr=0x4010,
        direct_call_count=2,
        callsite_kinds=("direct_far", "direct_near"),
        typed_ir_condition_kinds=("compare", "masked_nonzero"),
        typed_ir_register_clobbers=("cf", "ds"),
        typed_ir_address_spaces=("ds", "ss"),
        typed_ir_stable_address_spaces=("ss",),
        frame_slot_count=3,
    )
