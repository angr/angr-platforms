from angr_platforms.X86_16.low_memory_regions import (
    classify_x86_16_low_memory_access,
    format_x86_16_low_memory_access,
    linearize_x86_16_segment_offset,
)


def test_linearize_segment_offset_matches_bda_example():
    assert linearize_x86_16_segment_offset(0x40, 0x02) == 0x402


def test_classify_exact_bda_field_from_segment_offset():
    access = classify_x86_16_low_memory_access("0x40:0x17/1", access_kind="read")
    assert access is not None
    assert access.access_kind == "read"
    assert access.raw_access == "0x40:0x17/1"
    assert access.region == "bda"
    assert access.label == "bda.keyboard_flags0"
    assert access.linear == 0x417
    assert access.to_dict()["label"] == "bda.keyboard_flags0"


def test_classify_exact_bda_field_from_linear_address():
    access = classify_x86_16_low_memory_access("0x402/2", access_kind="write")
    assert access is not None
    assert access.access_kind == "write"
    assert access.raw_access == "0x402/2"
    assert access.label == "bda.com2_port"


def test_classify_video_ram_region_when_exact_field_absent():
    access = classify_x86_16_low_memory_access("0xb800:0x12", access_kind="read")
    assert access is not None
    assert access.region == "video_ram"
    assert access.label.startswith("video_ram.b800+0x")


def test_classify_region_only_when_size_mismatch_shifts_off_exact_field():
    access = classify_x86_16_low_memory_access("0x40:0x17/2", access_kind="read")
    assert access is not None
    assert access.region == "bda"
    assert access.label == "bda+0x17"
    assert access.raw_access == "0x40:0x17/2"
    assert access.size == 2


def test_format_low_memory_access_keeps_unknowns_unchanged():
    assert format_x86_16_low_memory_access("ds:si") == "ds:si"
