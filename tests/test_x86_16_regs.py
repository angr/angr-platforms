from __future__ import annotations

import pytest

from angr_platforms.X86_16.regs import coerce_reg16_t, coerce_reg32_t, coerce_sgreg_t, register_name_8616, reg16_t, reg32_t, sgreg_t


def test_register_coercion_accepts_plain_indices() -> None:
    assert coerce_reg16_t(0) == reg16_t.AX
    assert coerce_reg32_t(4) == reg32_t.ESP
    assert coerce_sgreg_t(2) == sgreg_t.SS


def test_register_coercion_rejects_non_constant_wrapper() -> None:
    class _BadValue:
        @property
        def value(self):
            raise ValueError("Non-constant VexValue has no value property")

    with pytest.raises(ValueError, match="Register .* does not exist"):
        coerce_reg16_t(_BadValue())


def test_register_name_rejects_non_constant_wrapper() -> None:
    class _BadValue:
        @property
        def value(self):
            raise ValueError("Non-constant VexValue has no value property")

    with pytest.raises(ValueError, match="Register .* does not exist"):
        register_name_8616(_BadValue())
