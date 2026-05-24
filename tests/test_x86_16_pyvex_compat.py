from __future__ import annotations

import pyvex.const as pyvex_const
import pyvex.block
from pyvex.lifting.util import vex_helper

import angr_platforms.X86_16  # noqa: F401
from inertia_decompiler.project_loading import _build_project_from_bytes


def test_pyvex_runtime_compatibility_is_applied() -> None:
    assert hasattr(pyvex_const.get_type_size, "cache_info")
    assert hasattr(pyvex_const.get_type_spec_size, "cache_info")
    assert vex_helper.Type.int_16 == vex_helper.Type.int_16


def test_pyvex_runtime_compatibility_avoids_eager_irsb_stringification(monkeypatch) -> None:
    original_str = pyvex.block.IRSB.__str__

    def _boom(self):  # noqa: ANN001
        raise AssertionError("IRSB.__str__ should not be called when debug logging is disabled")

    monkeypatch.setattr(pyvex.block.IRSB, "__str__", _boom)
    project = _build_project_from_bytes(b"\x55\x8b\xec\xb8\x01\x00\x5d\xc3", base_addr=0x1000, entry_point=0x1000)
    block = project.factory.block(0x1000, opt_level=0)
    irsb = block.vex_nostmt
    monkeypatch.setattr(pyvex.block.IRSB, "__str__", original_str)
    assert irsb is not None
