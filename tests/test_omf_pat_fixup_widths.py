from __future__ import annotations

from omf_pat import _omf_fixup_width_from_location_kind


def test_omf_fixup_width_mapping_known_x86_location_kinds() -> None:
    assert _omf_fixup_width_from_location_kind(0) == 1
    assert _omf_fixup_width_from_location_kind(1) == 2
    assert _omf_fixup_width_from_location_kind(2) == 2
    assert _omf_fixup_width_from_location_kind(3) == 4
    assert _omf_fixup_width_from_location_kind(5) == 2
    assert _omf_fixup_width_from_location_kind(9) == 4
    assert _omf_fixup_width_from_location_kind(11) == 6
    assert _omf_fixup_width_from_location_kind(13) == 4


def test_omf_fixup_width_mapping_unknown_kind_falls_back_conservatively() -> None:
    assert _omf_fixup_width_from_location_kind(4) == 2
    assert _omf_fixup_width_from_location_kind(15) == 2
