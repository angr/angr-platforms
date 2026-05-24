from angr_platforms.X86_16.readability_set import (
    GOLDEN_READABILITY_SET,
    describe_x86_16_golden_readability_set,
    summarize_x86_16_golden_readability_set,
)


def test_x86_16_golden_readability_set_names_expected_cases():
    cases = describe_x86_16_golden_readability_set()

    assert [case.proc_name for case in cases] == ["_mset_pos", "_ChangeWeather", "_start", "_max", "_ConfigCrts"]
    assert GOLDEN_READABILITY_SET == cases


def test_x86_16_golden_readability_set_carries_anchor_counts():
    summary = summarize_x86_16_golden_readability_set()

    assert summary[0] == ("cod/f14/MONOPRIN.COD", "_mset_pos", 5)
    assert summary[1] == ("cod/f14/NHORZ.COD", "_ChangeWeather", 5)
    assert summary[-1] == ("angr_platforms/x16_samples/COCKPIT.COD", "_ConfigCrts", 3)

