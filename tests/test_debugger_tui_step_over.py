from __future__ import annotations

import asyncio
from dataclasses import dataclass

from inertia_decompiler.gdb_client import StopInfo, StopReason
from inertia_decompiler.gdb_tui import GDBTUIApp


@dataclass
class FakeMemory:
    data: bytes


class FakeClient:
    def __init__(self) -> None:
        self.inserted: list[int] = []
        self.removed: list[int] = []
        self.continues = 0
        self.steps = 0

    async def read_memory(self, addr: int, length: int) -> FakeMemory:
        assert addr == 0x200
        assert length == 16
        return FakeMemory(data=bytes([0xE8, 0x34, 0x12]))

    async def insert_breakpoint(self, addr: int) -> str:
        self.inserted.append(addr)
        return "OK"

    async def remove_breakpoint(self, addr: int) -> str:
        self.removed.append(addr)
        return "OK"

    async def continue_(self) -> StopInfo:
        self.continues += 1
        return StopInfo(reason=StopReason.SIGTRAP, signal=5)

    async def step(self) -> StopInfo:
        self.steps += 1
        return StopInfo(reason=StopReason.SIGTRAP, signal=5)


def test_step_over_n_repeats_requested_count(monkeypatch) -> None:
    app = GDBTUIApp(arch="x86_16")
    calls: list[int] = []

    async def fake_once() -> StopInfo:
        calls.append(1)
        return StopInfo(reason=StopReason.SIGTRAP, signal=5)

    monkeypatch.setattr(app, "_step_over_once", fake_once)

    info = asyncio.run(app._step_over_n(7))

    assert info.reason is StopReason.SIGTRAP
    assert len(calls) == 7


def test_step_over_once_uses_temporary_breakpoint_for_calls(monkeypatch) -> None:
    app = GDBTUIApp(arch="x86_16")
    client = FakeClient()
    app._client = client
    app._current_ip = 0x200
    app._bps = {}

    monkeypatch.setattr(
        "inertia_decompiler.gdb_tui.disasm_x86",
        lambda data, addr, count, arch: [(addr, "call", "0x1437")],
    )

    info = asyncio.run(app._step_over_once())

    assert info.reason is StopReason.SIGTRAP
    assert client.inserted == [0x203]
    assert client.removed == [0x203]
    assert client.continues == 1
    assert client.steps == 0


def test_step_over_once_preserves_existing_breakpoint(monkeypatch) -> None:
    app = GDBTUIApp(arch="x86_16")
    client = FakeClient()
    app._client = client
    app._current_ip = 0x200
    app._bps = {0x203: {"enabled": True, "hits": 0}}

    monkeypatch.setattr(
        "inertia_decompiler.gdb_tui.disasm_x86",
        lambda data, addr, count, arch: [(addr, "call", "0x1437")],
    )

    asyncio.run(app._step_over_once())

    assert client.inserted == []
    assert client.removed == []
    assert client.continues == 1
