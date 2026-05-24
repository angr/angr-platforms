from __future__ import annotations

from omf_pat import _wildcard_far_transfer_opcode_variants


def test_far_call_fixup_variant_wildcards_opcode_for_linker_rewrite() -> None:
    function_bytes = [0x9A, None, None, None, None, 0xC3]
    rewritten = _wildcard_far_transfer_opcode_variants(function_bytes)
    assert rewritten == [None, None, None, None, None, 0xC3]


def test_far_transfer_variant_leaves_non_fixup_sequence_unchanged() -> None:
    function_bytes = [0x9A, 0x34, None, None, None, 0xC3]
    rewritten = _wildcard_far_transfer_opcode_variants(function_bytes)
    assert rewritten == function_bytes
