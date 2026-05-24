from __future__ import annotations

from pathlib import Path

import angr
import pytest

from angr_platforms.X86_16.ne_exe_parse import parse_ne_exe


ZEEK1_EXE = Path("/home/xor/games/zeek/ZEEK1.EXE")


@pytest.mark.skipif(not ZEEK1_EXE.exists(), reason="local Zeek NE sample is not available")
def test_zeek1_ne_loader_and_resources():
    project = angr.Project(
        ZEEK1_EXE,
        auto_load_libs=False,
        main_opts={"backend": "dos_ne", "base_addr": 0x1000},
        simos="DOS",
    )
    obj = project.loader.main_object

    assert len(obj.ne_segment_mappings) == 17
    assert obj.ne_resources is not None
    assert obj.ne_resources.kind == "win16"
    assert len(obj.ne_resources.groups) >= 4
    assert {group.name for group in obj.ne_resources.groups} >= {"GROUP_ICON", "BITMAP", "DIALOG", "ICON"}

    parsed = parse_ne_exe(ZEEK1_EXE, load_base_linear=getattr(obj, "linked_base", 0), project=project)
    assert parsed.code_labels
    assert parsed.entry_offsets

