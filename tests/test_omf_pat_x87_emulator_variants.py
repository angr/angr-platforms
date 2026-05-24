from __future__ import annotations

from omf_pat import _looks_like_msvc_fpu_runtime, _x87_emulator_variant_bytes


def test_x87_emulator_variant_rewrites_known_microsoft_pairs() -> None:
    function_bytes = [
        0x55,
        0x8B,
        0xEC,
        0x9B,
        0xD9,
        0xC9,
        0x9B,
        0xDE,
        0x9B,
        0xDD,
        0x7E,
        0xFE,
        0x90,
        0x9B,
        0xC3,
    ]

    rewritten = _x87_emulator_variant_bytes(function_bytes)

    assert rewritten == [
        0x55,
        0x8B,
        0xEC,
        0xCD,
        0x35,
        0xC9,
        0xCD,
        0x3A,
        0xCD,
        0x39,
        0x7E,
        0xFE,
        0xCD,
        0x3D,
        0xC3,
    ]


def test_x87_emulator_variant_leaves_nonmatching_bytes_unchanged() -> None:
    function_bytes = [0x55, 0x8B, 0xEC, 0xD9, 0xC9, 0xC3]

    rewritten = _x87_emulator_variant_bytes(function_bytes)

    assert rewritten == function_bytes


def test_msvc_fpu_runtime_gate_requires_microsoft_c_provenance() -> None:
    assert _looks_like_msvc_fpu_runtime(
        "__fcmp",
        (),
        compiler_name="Microsoft C v5.1",
    )
    assert not _looks_like_msvc_fpu_runtime(
        "__fcmp",
        (),
        compiler_name="Borland C++ 3.1",
    )
