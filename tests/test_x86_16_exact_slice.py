from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from angr_platforms.X86_16.lst_extract import LSTMetadata

from inertia_decompiler import cli
from inertia_decompiler.x86_16_exact_slice import (
    SAFE_X86_16_SLICE_BASE,
    function_original_addr,
    mark_function_original_addr,
    plan_x86_16_exact_slice,
)


def test_plan_x86_16_exact_slice_rebases_high_linear_addresses() -> None:
    plan = plan_x86_16_exact_slice(0x109E8, 0x10A61)
    assert plan.needs_rebased_slice is True
    assert plan.slice_start == SAFE_X86_16_SLICE_BASE
    assert plan.slice_end == SAFE_X86_16_SLICE_BASE + (0x10A61 - 0x109E8)


def test_function_original_addr_prefers_marked_original() -> None:
    function = SimpleNamespace(addr=0x1000, info={})
    mark_function_original_addr(function, 0x109E8)
    assert function_original_addr(function) == 0x109E8


def test_recover_lst_function_uses_rebased_slice_for_high_exact_region(monkeypatch) -> None:
    built = {}

    class FakeMemory:
        def load(self, addr: int, size: int) -> bytes:
            assert addr == 0x109E8
            assert size == 0x79
            return b"\x90" * size

    project = SimpleNamespace(
        arch=SimpleNamespace(name="86_16"),
        entry=0x10F9A,
        loader=SimpleNamespace(memory=FakeMemory()),
    )
    metadata = LSTMetadata(
        data_labels={},
        code_labels={0x109E8: "PercolateUp"},
        code_ranges={0x109E8: (0x109E8, 0x10A61)},
        absolute_addrs=True,
        cod_path=str(Path("/tmp/fake.cod")),
    )

    def fake_build_project_from_bytes(code: bytes, *, base_addr: int, entry_point: int):
        built["base_addr"] = base_addr
        built["entry_point"] = entry_point
        built["size"] = len(code)
        return SimpleNamespace(arch=SimpleNamespace(name="86_16"))

    def fake_pick_function_lean(slice_project, addr, *, regions, data_references, extend_far_calls):
        built["recover_addr"] = addr
        built["regions"] = regions
        function = SimpleNamespace(addr=addr, name="sub", info={}, project=slice_project)
        return SimpleNamespace(functions={addr: function}), function

    monkeypatch.setattr(cli, "_build_project_from_bytes", fake_build_project_from_bytes)
    monkeypatch.setattr(cli, "_inherit_tail_validation_runtime_policy", lambda slice_project, source_project: None)
    monkeypatch.setattr(cli, "_pick_function_lean", fake_pick_function_lean)

    cfg, function = cli._recover_lst_function(
        project,
        metadata,
        0x109E8,
        "PercolateUp",
        timeout=5,
        window=0x200,
    )

    assert cfg is not None
    assert built["base_addr"] == SAFE_X86_16_SLICE_BASE
    assert built["entry_point"] == SAFE_X86_16_SLICE_BASE
    assert built["recover_addr"] == SAFE_X86_16_SLICE_BASE
    assert built["regions"] == [(SAFE_X86_16_SLICE_BASE, SAFE_X86_16_SLICE_BASE + 0x79)]
    assert function.name == "PercolateUp"
    assert function_original_addr(function) == 0x109E8
