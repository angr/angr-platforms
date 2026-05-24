from __future__ import annotations

from bitstring import ConstBitStream

from angr_platforms.X86_16.exec import ExecInstr
from angr_platforms.X86_16.instruction import (
    CHK_IMM8,
    CHK_IMM16,
    CHK_MODRM,
    CHK_MOFFS,
    CHK_PTR16,
    InstrData,
    X86Instruction,
)
from angr_platforms.X86_16.parse import ParseInstr


class _DecodeEmu:
    def __init__(self, data: bytes, mode32: bool = False):
        self.bitstream = ConstBitStream(bytes=data)
        self._mode32 = mode32

    def is_mode32(self):
        return self._mode32

    def get_code8(self, _offset):
        return self.bitstream.read("uint:8")

    def get_code16(self, _offset):
        return self.bitstream.read("uintle:16")

    def get_code32(self, _offset):
        return self.bitstream.read("uintle:32")

    def constant(self, value, _ty):
        return value


def _parse_bytes(data: bytes, opcode: int, flags: int, *, mode32: bool = False) -> InstrData:
    instr = InstrData()
    parser = ParseInstr(_DecodeEmu(data, mode32=mode32), instr, mode32=mode32)
    parser.chk[opcode] = flags
    parser.parse_prefix()
    parser.parse()
    return instr


def test_decode_metadata_tracks_effective_widths_and_repeat_prefixes():
    instr = _parse_bytes(b"\x66\x67\xf3\xa1\x34\x12\x00\x00", 0xA1, CHK_MOFFS, mode32=False)

    assert instr.operand_bits == 32
    assert instr.address_bits == 32
    assert instr.width_case == "32/32"
    assert instr.displacement_bits == 32
    assert instr.repeat_class == "repz"
    assert instr.control_flow_class == "none"
    assert instr.prefix_len == 3


def test_decode_metadata_tracks_modrm_displacement_and_indirect_control_flow():
    instr = _parse_bytes(b"\xff\x16\x34\x12", 0xFF, CHK_MODRM, mode32=False)

    assert instr.address_bits == 16
    assert instr.displacement_bits == 16
    assert instr.control_flow_class == "near_call"


def test_decode_metadata_classifies_far_call_and_conditional_jump():
    far_call = _parse_bytes(b"\x9a\x34\x12\x78\x56", 0x9A, CHK_PTR16 | CHK_IMM16, mode32=False)
    jcc = _parse_bytes(b"\x74\x05", 0x74, CHK_IMM8, mode32=False)

    assert far_call.control_flow_class == "far_call"
    assert jcc.control_flow_class == "conditional_jump"


def test_exec_reads_normalized_address_bits_from_instruction_metadata():
    source = ExecInstr.calc_modrm.__code__.co_names + ExecInstr._resolved_rm_operand.__code__.co_names
    assert "effective_address_bits" in source


def test_instruction_api_exposes_effective_decode_facts():
    instr = InstrData()
    instr.operand_bits = 32
    instr.address_bits = 16
    instr.width_case = "32/16"
    instr.repeat_class = "repz"
    instr.control_flow_class = "near_call"

    view = X86Instruction(_DecodeEmu(b""), instr, mode32=False)

    assert view.effective_operand_bits() == 32
    assert view.effective_address_bits() == 16
    assert view.repeat_kind() == "repz"
    assert view.control_flow_kind() == "near_call"
    assert view.width_case_name() == "32/16"
    assert view.width_profile().operand_bits == 32
    assert view.width_profile().address_bits == 16
