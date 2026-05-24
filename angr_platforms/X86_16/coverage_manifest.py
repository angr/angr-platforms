from __future__ import annotations

# Opcode files whose semantics already have direct upstream-x86 compare coverage in
# tests/test_x86_16_compare_semantics.py. Skipping them in large MOO sweeps keeps the
# hardware-backed verifier focused on areas where the 286 corpus adds unique value.
COMPARE_VERIFIED_MOO_OPCODES = frozenset(
    {
        "15",
        "1A",
        "27",
        "2F",
        "37",
        "3F",
        "83.3",
        "85",
        "91",
        "98",
        "99",
        "9E",
        "9F",
        "A4",
        "A6",
        "AA",
        "AB",
        "AC",
        "AD",
        "AE",
        "AF",
        "D0.1",
        "D0.7",
        "D1.3",
        "D3.0",
        "D3.1",
        "D3.2",
        "D3.3",
        "D3.4",
        "D3.5",
        "D4",
        "D5",
        "D7",
        "E2",
        "F5",
        "F7.2",
        "F7.3",
        "F7.5",
        "F8",
        "F9",
    }
)
