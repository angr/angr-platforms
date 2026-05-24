from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler import cli
from inertia_decompiler.x86_16_exact_slice import (
    X86ExactSlicePlan,
    non_optimized_slice_codegen_policy,
)


def test_non_optimized_slice_codegen_policy_enables_postprocess_for_x86_exact_slice() -> None:
    slice_plan = X86ExactSlicePlan(
        original_start=0x10768,
        original_end=0x10794,
        slice_base=0x1000,
    )

    assert non_optimized_slice_codegen_policy("86_16", slice_plan) == (False, True)


def test_non_optimized_slice_codegen_policy_keeps_other_lanes_conservative() -> None:
    assert non_optimized_slice_codegen_policy("X86", None) == (False, False)
    assert non_optimized_slice_codegen_policy("86_16", None) == (False, False)


def test_try_decompile_non_optimized_slice_uses_exact_slice_postprocess_policy(monkeypatch) -> None:
    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        loader=SimpleNamespace(memory=SimpleNamespace(load=lambda *_args, **_kwargs: b"\x90\x90\xc3")),
    )
    function = SimpleNamespace(name="SwapBars", addr=0x1000, normalized=True, blocks=(SimpleNamespace(size=0x10),), info={})
    captured: dict[str, object] = {}

    monkeypatch.setattr(cli, "_lst_code_region", lambda *_args, **_kwargs: (0x10768, 0x1076B))
    monkeypatch.setattr(cli, "_build_project_from_bytes", lambda *args, **kwargs: SimpleNamespace(arch=SimpleNamespace(name="86_16")))
    monkeypatch.setattr(cli, "_pick_function_lean", lambda *_args, **_kwargs: (SimpleNamespace(), function))
    monkeypatch.setattr(cli, "_inherit_tail_validation_runtime_policy", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "_prepare_function_for_decompilation", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "_run_with_timeout_in_daemon_thread", lambda fn, **_kwargs: fn())

    def _fake_decompile(*_args, **kwargs):
        captured["enable_structured_simplify"] = kwargs["enable_structured_simplify"]
        captured["enable_postprocess"] = kwargs["enable_postprocess"]
        return ("ok", "void SwapBars(void) {}", None, 1, 3, 0.01)

    monkeypatch.setattr(cli, "_decompile_function_with_stats", _fake_decompile)

    outcome = cli._try_decompile_non_optimized_slice(
        project,
        0x10768,
        "SwapBars",
        timeout=1,
        api_style="modern",
        binary_path=None,
        lst_metadata=None,
        allow_fresh_project_retry=False,
    )

    assert outcome.rendered == "void SwapBars(void) {}"
    assert captured == {
        "enable_structured_simplify": False,
        "enable_postprocess": True,
    }
