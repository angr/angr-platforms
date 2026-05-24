from pyvex.lifting.util.vex_helper import Type

from angr_platforms.X86_16.addressing_helpers import (
    ResolvedMemoryOperand,
    WidthProfile,
    address_step,
    address_width_bits,
    advance_eip32,
    advance_ip16,
    decode_width_case,
    decode_width_case_for_profile,
    decode_width_profile,
    default_segment_for_modrm16,
    default_segment_for_modrm32,
    describe_x86_16_decode_width_matrix,
    describe_x86_16_mixed_width_extension_surface,
    displacement_width_bits,
    linear_address,
    load_far_pointer,
    load_far_pointer16,
    load_resolved_operand,
    load_word_pair16,
    modrm16_effective_offset,
    modrm32_effective_offset,
    operand_width_bits,
    resolve_linear_operand,
    resolve_modrm16_address,
    resolve_modrm32_address,
    signed_displacement,
    store_resolved_operand,
)
from angr_platforms.X86_16.regs import reg16_t, reg32_t, sgreg_t


class _FakeEmu:
    def __init__(self):
        self.calls = []
        self.loads = []
        self.stores = []
        self.gpregs = {}

    def constant(self, value, ty):
        self.calls.append((value, ty))
        return (value, ty)

    def get_gpreg(self, reg):
        return self.gpregs.get(reg, 0)

    def v2p(self, segment, offset):
        return (segment, offset)

    def get_data8(self, segment, offset):
        self.loads.append((segment, offset))
        return ("byte", segment, offset)

    def get_data16(self, segment, offset):
        self.loads.append((segment, offset))
        return ("word", segment, offset)

    def get_data32(self, segment, offset):
        self.loads.append((segment, offset))
        return ("dword", segment, offset)

    def put_data8(self, segment, offset, value):
        self.stores.append((8, segment, offset, value))

    def put_data16(self, segment, offset, value):
        self.stores.append((16, segment, offset, value))

    def put_data32(self, segment, offset, value):
        self.stores.append((32, segment, offset, value))


def test_width_helpers_cover_real_mode_and_386_extension_paths():
    assert operand_width_bits(False, False) == 16
    assert operand_width_bits(False, True) == 32
    assert operand_width_bits(True, False) == 32
    assert operand_width_bits(True, True) == 16

    assert address_width_bits(False, False) == 16
    assert address_width_bits(False, True) == 32
    assert address_width_bits(True, False) == 32
    assert address_width_bits(True, True) == 16


def test_displacement_helpers_normalize_signed_values_and_widths():
    assert signed_displacement(0x7F, 8) == 127
    assert signed_displacement(0x80, 8) == -128
    assert signed_displacement(0xFF, 8) == -1

    assert displacement_width_bits(0, 6, 16) == 16
    assert displacement_width_bits(1, 0, 16) == 8
    assert displacement_width_bits(2, 7, 16) == 16
    assert displacement_width_bits(0, 5, 32) == 32
    assert displacement_width_bits(1, 2, 32) == 8
    assert displacement_width_bits(2, 2, 32) == 32


def test_address_step_uses_bit_width_specific_constants():
    emu = _FakeEmu()

    sixteen = address_step(emu, 2, 16)
    thirty_two = address_step(emu, 4, 32)

    assert emu.calls[0][0] == 2
    assert emu.calls[1][0] == 4
    assert emu.calls[0][1] == Type.int_16
    assert emu.calls[1][1] == Type.int_32
    assert sixteen == (2, emu.calls[0][1])
    assert thirty_two == (4, emu.calls[1][1])


def test_advance_ip_helpers_use_bit_width_specific_constants():
    class _AdvanceFakeEmu(_FakeEmu):
        def constant(self, value, ty):
            self.calls.append((value, ty))
            return value

    emu = _AdvanceFakeEmu()
    emu.gpregs[sgreg_t.CS] = 0x1234
    emu.gpregs[sgreg_t.DS] = 0x5678
    emu.gpregs[sgreg_t.SS] = 0x9ABC
    emu.gpregs[reg16_t.IP] = 0x0100
    emu.gpregs[reg32_t.EIP] = 0x0200

    assert advance_ip16(emu, 4) == 0x0104
    assert advance_eip32(emu, 8) == 0x0208
    assert emu.calls == [(4, Type.int_16), (8, Type.int_32)]


def test_linear_address_reuses_project_linear_translation():
    emu = _FakeEmu()

    assert linear_address(emu, sgreg_t.DS, 0x1234) == (sgreg_t.DS, 0x1234)


def test_default_segment_helpers_match_x86_16_addressing_rules():
    assert default_segment_for_modrm16(0, 0) == sgreg_t.DS
    assert default_segment_for_modrm16(0, 6) == sgreg_t.DS
    assert default_segment_for_modrm16(1, 2) == sgreg_t.SS
    assert default_segment_for_modrm16(2, 3) == sgreg_t.SS

    assert default_segment_for_modrm32(0, 0) == sgreg_t.DS
    assert default_segment_for_modrm32(0, 4, 4) == sgreg_t.SS
    assert default_segment_for_modrm32(0, 4, 5) == sgreg_t.SS
    assert default_segment_for_modrm32(0, 4, 0) == sgreg_t.DS
    assert default_segment_for_modrm32(1, 5) == sgreg_t.SS


def test_modrm16_effective_offset_reuses_shared_address_rules():
    class _MathFakeEmu(_FakeEmu):
        def constant(self, value, ty):
            self.calls.append((value, ty))
            return value

    emu = _MathFakeEmu()
    emu.gpregs[reg16_t.BX] = 0x0100
    emu.gpregs[reg16_t.BP] = 0x0200
    emu.gpregs[reg16_t.SI] = 0x0300
    emu.gpregs[reg16_t.DI] = 0x0400

    class _Modrm:
        def __init__(self, mod, rm):
            self.mod = mod
            self.rm = rm

    addr = modrm16_effective_offset(emu, _Modrm(1, 1), 0x10, 0x2222)
    assert emu.calls[0] == (0, Type.int_16)
    assert emu.calls[1] == (0x10, Type.int_16)
    assert addr == 0x0510


def test_modrm32_effective_offset_handles_sib_base_and_no_index():
    class _MathFakeEmu(_FakeEmu):
        def constant(self, value, ty):
            self.calls.append((value, ty))
            return value

    class _Modrm:
        def __init__(self, mod, rm):
            self.mod = mod
            self.rm = rm

    class _SIB:
        def __init__(self, base, index, scale):
            self.base = base
            self.index = index
            self.scale = scale

    emu = _MathFakeEmu()
    emu.gpregs[reg32_t.EAX] = 0x2000
    emu.gpregs[reg32_t.ESP] = 0x1000
    emu.gpregs[reg32_t.ECX] = 0x0040
    emu.gpregs[reg32_t.EDX] = 0x0300

    addr = modrm32_effective_offset(emu, _Modrm(0, 4), _SIB(4, 4, 1), 0x10, 0x4444)
    assert addr == 0x1000

    addr = modrm32_effective_offset(emu, _Modrm(0, 4), _SIB(5, 4, 1), 0x10, 0x4444)
    assert addr == 0x4444

    addr = modrm32_effective_offset(emu, _Modrm(0, 4), _SIB(0, 4, 2), 0x10, 0x4444)
    assert addr == 0x2000

    addr = modrm32_effective_offset(emu, _Modrm(0, 4), _SIB(0, 1, 2), 0x10, 0x4444)
    assert addr == 0x2000 + (0x0040 << 2)


def test_resolve_modrm_address_pairs_segment_and_offset():
    class _MathFakeEmu(_FakeEmu):
        def constant(self, value, ty):
            self.calls.append((value, ty))
            return value

    class _Modrm:
        def __init__(self, mod, rm):
            self.mod = mod
            self.rm = rm

    class _SIB:
        def __init__(self, base, index, scale):
            self.base = base
            self.index = index
            self.scale = scale

    emu = _MathFakeEmu()
    emu.gpregs[reg16_t.BX] = 0x0100
    emu.gpregs[reg16_t.SI] = 0x0200
    emu.gpregs[reg32_t.EAX] = 0x2000
    emu.gpregs[reg32_t.ESP] = 0x1000

    segment, offset = resolve_modrm16_address(emu, _Modrm(1, 0), 0x10, 0x2222)
    assert segment == sgreg_t.DS
    assert offset == 0x0310

    segment, offset = resolve_modrm32_address(emu, _Modrm(0, 4), _SIB(4, 4, 1), 0x10, 0x4444)
    assert segment == sgreg_t.SS
    assert offset == 0x1000


def test_resolved_memory_operand_tracks_segment_offset_and_linear_form():
    emu = _FakeEmu()

    resolved = resolve_linear_operand(emu, sgreg_t.DS, 0x1234, 16, 16)

    assert isinstance(resolved, ResolvedMemoryOperand)
    assert resolved.segment == sgreg_t.DS
    assert resolved.offset == 0x1234
    assert resolved.linear == (sgreg_t.DS, 0x1234)
    assert resolved.width_bits == 16
    assert resolved.address_bits == 16


def test_width_profile_exposes_byte_counts():
    profile = WidthProfile(operand_bits=32, address_bits=16)

    assert profile.operand_bytes == 4
    assert profile.address_bytes == 2


def test_decode_width_profile_covers_explicit_mixed_width_matrix():
    assert decode_width_profile(False, False, False) == WidthProfile(operand_bits=16, address_bits=16)
    assert decode_width_profile(False, True, False) == WidthProfile(operand_bits=32, address_bits=16)
    assert decode_width_profile(False, False, True) == WidthProfile(operand_bits=16, address_bits=32)
    assert decode_width_profile(True, False, False) == WidthProfile(operand_bits=32, address_bits=32)


def test_decode_width_case_returns_named_matrix_entries():
    assert decode_width_case(False, False, False).name == "16/16"
    assert decode_width_case(False, True, False).name == "32/16"
    assert decode_width_case(False, False, True).name == "16/32"
    assert decode_width_case(True, False, False).name == "32/32"


def test_decode_width_case_for_profile_resolves_mixed_width_matrix_entries():
    assert decode_width_case_for_profile(16, 16).name == "16/16"
    assert decode_width_case_for_profile(32, 16).name == "32/16"
    assert decode_width_case_for_profile(16, 32).name == "16/32"
    assert decode_width_case_for_profile(32, 32).name == "32/32"


def test_describe_x86_16_decode_width_matrix_exposes_named_cases():
    assert describe_x86_16_decode_width_matrix() == (
        ("16/16", 16, 16),
        ("32/16", 32, 16),
        ("16/32", 16, 32),
        ("32/32", 32, 32),
    )


def test_describe_x86_16_mixed_width_extension_surface_matches_matrix():
    assert describe_x86_16_mixed_width_extension_surface() == {
        "matrix": (
            {
                "name": "16/16",
                "operand_bits": 16,
                "address_bits": 16,
                "mode32": False,
                "chsz_op": False,
                "chsz_ad": False,
            },
            {
                "name": "32/16",
                "operand_bits": 32,
                "address_bits": 16,
                "mode32": False,
                "chsz_op": True,
                "chsz_ad": False,
            },
            {
                "name": "16/32",
                "operand_bits": 16,
                "address_bits": 32,
                "mode32": False,
                "chsz_op": False,
                "chsz_ad": True,
            },
            {
                "name": "32/32",
                "operand_bits": 32,
                "address_bits": 32,
                "mode32": True,
                "chsz_op": False,
                "chsz_ad": False,
            },
        ),
        "supported_pairs": ((16, 16), (32, 16), (16, 32), (32, 32)),
        "address_widths": (16, 32),
        "operand_widths": (16, 32),
    }


def test_load_far_pointer16_uses_address_width_specific_step():
    emu = _FakeEmu()

    offset, segment = load_far_pointer16(emu, sgreg_t.DS, 0x1234, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (2, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert offset == ("word", sgreg_t.DS, typed_offset)
    assert segment == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_load_word_pair16_uses_address_width_specific_step():
    emu = _FakeEmu()

    first, second = load_word_pair16(emu, sgreg_t.DS, 0x1234, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (2, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert first == ("word", sgreg_t.DS, typed_offset)
    assert second == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_load_far_pointer_supports_future_32_bit_operand_widths():
    emu = _FakeEmu()

    offset, segment = load_far_pointer(emu, sgreg_t.DS, 0x1234, 32, address_bits=16)

    assert emu.calls == [(0x1234, Type.int_16), (4, Type.int_16)]
    typed_offset = (0x1234, Type.int_16)
    assert emu.loads[0] == (sgreg_t.DS, typed_offset)
    assert emu.loads[1] == (sgreg_t.DS, typed_offset + emu.calls[1])
    assert offset == ("dword", sgreg_t.DS, typed_offset)
    assert segment == ("word", sgreg_t.DS, typed_offset + emu.calls[1])


def test_resolved_memory_helpers_dispatch_by_operand_width():
    emu = _FakeEmu()

    byte_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x10, 8, 16)
    word_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x20, 16, 16)
    dword_operand = resolve_linear_operand(emu, sgreg_t.DS, 0x30, 32, 16)

    assert load_resolved_operand(emu, byte_operand)[0] == "byte"
    assert load_resolved_operand(emu, word_operand)[0] == "word"
    assert load_resolved_operand(emu, dword_operand)[0] == "dword"

    store_resolved_operand(emu, byte_operand, 0x11)
    store_resolved_operand(emu, word_operand, 0x2222)
    store_resolved_operand(emu, dword_operand, 0x33333333)

    assert emu.stores == [
        (8, sgreg_t.DS, 0x10, 0x11),
        (16, sgreg_t.DS, 0x20, 0x2222),
        (32, sgreg_t.DS, 0x30, 0x33333333),
    ]
