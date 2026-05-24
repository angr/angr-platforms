from __future__ import annotations

from omf_pat import _wildcard_zero_displacement_control_transfers


def test_wildcard_zero_displacement_control_transfers_rewrites_near_and_far_calls():
    data = [
        0x90,
        0xE8, 0x00, 0x00,
        0xE9, 0x00, 0x00,
        0x9A, 0x00, 0x00, 0x00, 0x00,
        0xEA, 0x00, 0x00, 0x00, 0x00,
        0x90,
    ]

    rewritten = _wildcard_zero_displacement_control_transfers(data)

    assert rewritten == [
        0x90,
        0xE8, None, None,
        0xE9, None, None,
        0x9A, None, None, None, None,
        0xEA, None, None, None, None,
        0x90,
    ]
