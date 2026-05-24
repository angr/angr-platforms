from __future__ import annotations

import io
from pathlib import Path

import angr
import pytest
import pyvex

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.load_dos_mz import DOSMZ, DOSMZHeader  # noqa: F401
from angr_platforms.X86_16.simos_86_16 import (
    INTERRUPT_VECTOR_COUNT,
    BIOSInt12MemorySize,
    DOSInt21,
    interrupt_addr,
)

T_EXE_PATH = Path("/home/xor/games/f15se2-re/T.EXE")
T_COD_PATH = Path("/home/xor/games/f15se2-re/T.COD")


def _blob_project(code: bytes):
    return angr.Project(
        io.BytesIO(code),
        main_opts={
            "backend": "blob",
            "arch": Arch86_16(),
            "base_addr": 0x1000,
            "entry_point": 0x1000,
        },
        simos="DOS",
    )


def _read_mz_header(path: Path) -> dict[str, int]:
    data = path.read_bytes()[:0x40]
    return {
        "header_paragraphs": int.from_bytes(data[0x08:0x0A], "little"),
        "ss": int.from_bytes(data[0x0E:0x10], "little"),
        "sp": int.from_bytes(data[0x10:0x12], "little"),
        "ip": int.from_bytes(data[0x14:0x16], "little"),
        "cs": int.from_bytes(data[0x16:0x18], "little"),
    }


def test_dos_mz_header_parser_reads_core_fields():
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x06:0x08] = (3).to_bytes(2, "little")
    header[0x08:0x0A] = (4).to_bytes(2, "little")
    header[0x0E:0x10] = (0x1111).to_bytes(2, "little")
    header[0x10:0x12] = (0x2222).to_bytes(2, "little")
    header[0x14:0x16] = (0x3333).to_bytes(2, "little")
    header[0x16:0x18] = (0x4444).to_bytes(2, "little")
    header[0x18:0x1A] = (0x20).to_bytes(2, "little")

    parsed = DOSMZHeader.from_stream(io.BytesIO(bytes(header)))

    assert parsed.header_paragraphs == 4
    assert parsed.relocation_count == 3
    assert parsed.relocation_offset == 0x20
    assert parsed.initial_ip == 0x3333
    assert parsed.initial_cs == 0x4444
    assert parsed.initial_sp == 0x2222
    assert parsed.initial_ss == 0x1111


def test_dos_mz_loader_infers_segment_spans_from_entry_stack_and_relocations(tmp_path):
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x06:0x08] = (2).to_bytes(2, "little")
    header[0x08:0x0A] = (4).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0010).to_bytes(2, "little")
    header[0x10:0x12] = (0x0020).to_bytes(2, "little")
    header[0x14:0x16] = (0x0030).to_bytes(2, "little")
    header[0x16:0x18] = (0x0000).to_bytes(2, "little")
    header[0x18:0x1A] = (0x20).to_bytes(2, "little")
    header[0x20:0x24] = (0x0002).to_bytes(2, "little") + (0x0000).to_bytes(2, "little")
    header[0x24:0x28] = (0x0004).to_bytes(2, "little") + (0x0010).to_bytes(2, "little")
    image = bytes(index & 0xFF for index in range(0x140))
    sample = tmp_path / "segments.exe"
    sample.write_bytes(bytes(header) + image)

    with sample.open("rb") as fp:
        obj = DOSMZ(str(sample), fp, base_addr=0x1000)

    assert [(span.segment, span.evidence) for span in obj.mz_segment_spans] == [
        (0x0000, ("entry_cs:ip", "relocation")),
        (0x0010, ("relocation", "stack_ss:sp")),
    ]
    assert obj.mz_segment_spans[0].start_linear == 0x1000
    assert obj.mz_segment_spans[0].end_linear == 0x110F
    assert obj.mz_segment_spans[1].start_linear == 0x1100
    assert obj.mz_segment_spans[1].end_linear == 0x1140


def test_dos_mz_loader_allows_up_to_fifteen_bytes_of_overlap_between_neighbor_segments(tmp_path):
    header = bytearray(0x40)
    header[0:2] = b"MZ"
    header[0x06:0x08] = (1).to_bytes(2, "little")
    header[0x08:0x0A] = (4).to_bytes(2, "little")
    header[0x0E:0x10] = (0x0002).to_bytes(2, "little")
    header[0x10:0x12] = (0x0000).to_bytes(2, "little")
    header[0x14:0x16] = (0x0000).to_bytes(2, "little")
    header[0x16:0x18] = (0x0001).to_bytes(2, "little")
    header[0x18:0x1A] = (0x20).to_bytes(2, "little")
    header[0x20:0x24] = (0x0000).to_bytes(2, "little") + (0x0000).to_bytes(2, "little")
    sample = tmp_path / "overlap.exe"
    sample.write_bytes(bytes(header) + b"\x90" * 0x60)

    with sample.open("rb") as fp:
        obj = DOSMZ(str(sample), fp, base_addr=0x1000)

    spans = obj.mz_segment_spans
    assert len(spans) == 3
    assert spans[0].end_linear - spans[1].start_linear == 0x0F
    assert spans[1].end_linear - spans[2].start_linear == 0x0F


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_backend_loads_real_executable():
    header = _read_mz_header(T_EXE_PATH)
    project = angr.Project(T_EXE_PATH)
    load_segment = project.loader.main_object.mz_load_segment

    assert isinstance(project.loader.main_object, DOSMZ)
    assert isinstance(project.arch, Arch86_16)
    assert project.loader.main_object.os == "DOS"
    assert project.loader.main_object.mz_image_offset == header["header_paragraphs"] * 0x10
    assert project.loader.main_object.initial_register_values == {
        "cs": header["cs"] + load_segment,
        "ip": header["ip"],
        "ss": header["ss"] + load_segment,
        "sp": header["sp"],
    }
    assert project.entry == project.loader.main_object.linked_base + (header["cs"] << 4) + header["ip"]


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_entry_block_lifts_under_x86_16():
    project = angr.Project(T_EXE_PATH)

    block = project.factory.block(project.entry, size=8)
    asm = "\n".join(f"{insn.mnemonic} {insn.op_str}".strip() for insn in block.capstone.insns).lower()

    assert "mov ah, 0x30" in asm
    assert "int 0x21" in asm


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_entry_block_routes_int21_to_synthetic_call():
    project = angr.Project(T_EXE_PATH)

    block = project.factory.block(project.entry, size=8, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"
    assert isinstance(block.vex.next, pyvex.expr.Const)
    assert block.vex.next.con.value == interrupt_addr(0x21)


@pytest.mark.skipif(not T_EXE_PATH.exists(), reason="f15se2-re test executable is not available")
def test_dos_mz_project_hooks_int21_target_as_dos_helper():
    project = angr.Project(T_EXE_PATH)

    assert project.simos.name == "DOS"
    assert project.is_hooked(interrupt_addr(0x21))
    assert isinstance(project.hooked_by(interrupt_addr(0x21)), DOSInt21)


def test_medium_model_far_call_block_lifts():
    project = angr.Project(Path(__file__).resolve().parents[1] / "x16_samples" / "IMOD.EXE")

    block = project.factory.block(0x1180, size=8, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"


def test_simos_hooks_all_interrupt_vectors():
    project = angr.load_shellcode(b"\xCD\x10\xC3", arch="X86_16", simos="DOS")

    for vector in range(INTERRUPT_VECTOR_COUNT):
        assert project.is_hooked(interrupt_addr(vector))


def test_shellcode_interrupt_targets_match_vector_number():
    project = _blob_project(b"\xCD\x10\xC3")

    block = project.factory.block(0x1000, opt_level=0)

    assert block.vex.jumpkind == "Ijk_Call"
    assert isinstance(block.vex.next, pyvex.expr.Const)
    assert block.vex.next.con.value == interrupt_addr(0x10)


def test_bios_and_dos_interrupt_handlers_have_basic_semantics():
    bios_project = angr.load_shellcode(b"\x90", arch="X86_16", simos="DOS")
    bios_state = bios_project.factory.call_state(addr=interrupt_addr(0x12), ret_addr=0)
    bios_result = bios_project.factory.callable(
        interrupt_addr(0x12), concrete_only=True, base_state=bios_state
    )()

    dos_project = angr.load_shellcode(b"\x90", arch="X86_16", simos="DOS")
    dos_state = dos_project.factory.call_state(addr=interrupt_addr(0x21), ret_addr=0)
    dos_state.regs.ah = 0x30
    dos_result = dos_project.factory.callable(
        interrupt_addr(0x21), concrete_only=True, base_state=dos_state
    )()

    assert isinstance(bios_project.hooked_by(interrupt_addr(0x12)), BIOSInt12MemorySize)
    assert bios_result.concrete_value == 640
    assert dos_result.concrete_value == 5


@pytest.mark.skipif(
    not T_EXE_PATH.exists() or not T_COD_PATH.exists(),
    reason="f15se2-re executable/COD pair is not available",
)
def test_real_executable_has_matching_cod_sidecar():
    cod_text = T_COD_PATH.read_text(errors="ignore")
    project = angr.Project(T_EXE_PATH)

    assert ";|*** int add(int a, int b)" in cod_text
    assert "_add\tPROC NEAR" in cod_text
    assert project.loader.main_object.binary_basename == "T.EXE"
