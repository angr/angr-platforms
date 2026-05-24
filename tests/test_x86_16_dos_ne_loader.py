from __future__ import annotations

import re
import tarfile
from pathlib import Path

import angr
import decompile
import pytest

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_ne import DOSNE, DOSNEHeader  # noqa: F401

REPO_ROOT = Path(__file__).resolve().parents[2]
MZ_EXPLODE_ARCHIVE = REPO_ROOT / "mz-explode" / "test" / "testdata.tar.gz"
PROGMAN_MEMBER = "testdata/ne/progman.cc"


def _extract_cc_fixture_bytes(member_name: str) -> bytes:
    if not MZ_EXPLODE_ARCHIVE.exists():
        pytest.skip("mz-explode test fixture archive is not available")
    with tarfile.open(MZ_EXPLODE_ARCHIVE, "r:gz") as archive:
        try:
            member = archive.extractfile(member_name)
        except KeyError:
            pytest.skip(f"{member_name} is not available in the mz-explode fixture archive")
        assert member is not None
        text = member.read().decode("utf-8", errors="ignore")
    values = re.findall(r"0x([0-9a-fA-F]{1,2})", text)
    return bytes(int(value, 16) for value in values)


def _progman_ne_path(tmp_path: Path) -> Path:
    sample = tmp_path / "progman.exe"
    sample.write_bytes(_extract_cc_fixture_bytes(PROGMAN_MEMBER))
    return sample


def test_dos_ne_header_parser_reads_core_fields(tmp_path):
    sample = _progman_ne_path(tmp_path)
    with sample.open("rb") as fp:
        header = DOSNEHeader.from_stream(fp)

    assert header.ne_header_offset == 0x400
    assert header.entry_ip == 0x0299
    assert header.entry_segment == 0x0001
    assert header.stack_sp == 0x0000
    assert header.stack_segment == 0x0008
    assert header.segment_count == 0x0008
    assert header.segment_table_offset == 0x0040
    assert header.alignment_shift == 0x0004
    assert header.target_os == 0x02


def test_dos_ne_backend_loads_progman_fixture_and_maps_segments(tmp_path):
    sample = _progman_ne_path(tmp_path)

    project = angr.Project(
        sample,
        auto_load_libs=False,
        main_opts={"backend": "dos_ne", "base_addr": 0x1000},
        simos="DOS",
    )

    obj = project.loader.main_object
    assert isinstance(obj, DOSNE)
    assert isinstance(project.arch, Arch86_16)
    assert obj.initial_register_values["cs"] == obj.ne_segment_mappings[0].selector
    assert obj.initial_register_values["ip"] == 0x0299
    assert obj.initial_register_values["ss"] == obj.ne_segment_mappings[7].selector
    assert project.entry == (obj.initial_register_values["cs"] << 4) + obj.initial_register_values["ip"]
    assert len(obj.ne_segment_mappings) == 8
    assert obj.ne_segment_mappings[0].file_offset == 0x0E20
    assert obj.ne_segment_mappings[0].length == 0x02F9
    assert obj.ne_resources is not None
    assert obj.ne_resources.kind in {"win16", "os2"}


def test_dos_ne_entry_block_lifts_under_x86_16(tmp_path):
    sample = _progman_ne_path(tmp_path)
    project = angr.Project(
        sample,
        auto_load_libs=False,
        main_opts={"backend": "dos_ne", "base_addr": 0x1000},
        simos="DOS",
    )

    block = project.factory.block(project.entry, size=8)
    mnemonics = [insn.mnemonic.lower() for insn in block.capstone.insns]

    assert mnemonics
    assert mnemonics[0] == "xor"
    assert "push" in mnemonics


def test_build_project_selects_dos_ne_for_ne_executable(tmp_path):
    sample = _progman_ne_path(tmp_path)

    project = decompile._build_project(sample, force_blob=False, base_addr=0x100, entry_point=0x1000)

    assert isinstance(project.loader.main_object, DOSNE)
    assert project.entry == (
        project.loader.main_object.initial_register_values["cs"] << 4
    ) + project.loader.main_object.initial_register_values["ip"]
