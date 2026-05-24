import sys
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DECOMPILE_PATH = REPO_ROOT / "decompile.py"

_spec = spec_from_file_location("decompile", DECOMPILE_PATH)
assert _spec is not None and _spec.loader is not None
_decompile = module_from_spec(_spec)
sys.modules[_spec.name] = _decompile
_spec.loader.exec_module(_decompile)

_access_trait_member_candidates = _decompile._access_trait_member_candidates
_build_access_trait_evidence_profiles = _decompile._build_access_trait_evidence_profiles
_AccessTraitRewriteDecision = _decompile._AccessTraitRewriteDecision
_AccessTraitStrideEvidence = _decompile._AccessTraitStrideEvidence


def test_access_trait_profiles_keep_member_array_and_induction_lanes_distinct():
    induction_evidence = _AccessTraitStrideEvidence(
        segment="ss",
        base_key=("stack", "bp", -4),
        index_key=("reg", 30),
        stride=16,
        offset=0,
        width=2,
        count=3,
        kind="induction_like",
    )
    traits = {
        "base_const": {
            ("ss", ("reg", 30), 4, 2): 5,
        },
        "base_stride": {
            ("ss", ("reg", 30), 16, 0, 2): 4,
        },
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {
            ("induction_like", "ss", ("stack", "bp", -4), ("reg", 30), 16, 0, 2): induction_evidence,
        },
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    profiles = _build_access_trait_evidence_profiles(traits)

    assert profiles == {
        ("reg", 30): _decompile._AccessTraitEvidenceProfile(
            member_like=((4, 2, 5),),
            array_like=((0, 2, 4),),
            induction_like=((0, 2, 3),),
            stack_like=(),
            induction_evidence=(induction_evidence,),
            stride_evidence=(),
        )
    }


def test_access_trait_stride_evidence_feeds_member_candidates():
    traits = {
        "base_const": {},
        "base_stride": {
            ("ss", ("reg", 30), 16, 0, 2): 4,
        },
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    candidates = _access_trait_member_candidates(traits)

    assert candidates == {("reg", 30): [(0, 2, 4)]}


def test_access_trait_induction_evidence_feeds_member_candidates():
    induction_evidence = _AccessTraitStrideEvidence(
        segment="ss",
        base_key=("stack", "bp", -4),
        index_key=("reg", 30),
        stride=16,
        offset=0,
        width=2,
        count=3,
        kind="induction_like",
    )
    traits = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {
            ("induction_like", "ss", ("stack", "bp", -4), ("reg", 30), 16, 0, 2): induction_evidence,
        },
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    candidates = _access_trait_member_candidates(traits)

    assert candidates == {("reg", 30): [(0, 2, 3)]}


def test_access_trait_profiles_track_stack_like_evidence():
    traits = {
        "base_const": {
            ("ss", ("stack", "bp", -4), 4, 2): 5,
        },
        "base_stride": {},
        "repeated_offsets": {
            ("ss", ("stack", "bp", -4), -4): 3,
        },
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "stride_evidence": {},
        "member_evidence": {},
        "array_evidence": {},
    }

    profiles = _build_access_trait_evidence_profiles(traits)

    assert profiles == {
        ("stack", "bp", -4): _decompile._AccessTraitEvidenceProfile(
            member_like=((-4, 1, 3), (4, 2, 5)),
            array_like=(),
            induction_like=(),
            stack_like=((-4, 1, 3), (4, 2, 5)),
        )
    }


def test_access_trait_stack_profiles_prefer_stack_like_naming_order():
    profile = _decompile._AccessTraitEvidenceProfile(
        member_like=((4, 2, 5),),
        array_like=((8, 2, 1),),
        induction_like=((12, 2, 2),),
        stack_like=((-4, 1, 3),),
    )

    assert profile.naming_candidates(("stack", "bp", -4)) == (
        (-4, 1, 3),
        (4, 2, 5),
        (8, 2, 1),
        (12, 2, 2),
    )
    assert _AccessTraitRewriteDecision(("stack", "bp", -4), profile).candidate_field_names() == (
        "field_-4",
        "field_4",
        "field_8",
        "field_c",
    )
    assert _AccessTraitRewriteDecision(("stack", "bp", -4), profile).preferred_kind() == "stack"
    assert profile.naming_candidates(("reg", 30)) == (
        (4, 2, 5),
        (8, 2, 1),
        (12, 2, 2),
        (-4, 1, 3),
    )


def test_access_trait_structured_stride_evidence_is_named_before_raw_counts():
    evidence = _AccessTraitStrideEvidence(
        segment="ss",
        base_key=("stack", "bp", -4),
        index_key=("reg", 30),
        stride=16,
        offset=8,
        width=2,
        count=1,
        kind="induction_like",
    )
    profile = _decompile._AccessTraitEvidenceProfile(
        member_like=((4, 2, 9),),
        induction_evidence=(evidence,),
        stride_evidence=(evidence,),
    )

    assert profile.naming_candidates(("reg", 30)) == ((8, 2, 1), (4, 2, 9))
    assert _AccessTraitRewriteDecision(("reg", 30), profile).candidate_field_names() == (
        "field_8",
        "field_4",
    )


def test_access_trait_profiles_preserve_structured_stride_evidence():
    evidence = _AccessTraitStrideEvidence(
        segment="ss",
        base_key=("stack", "bp", -4),
        index_key=("reg", 30),
        stride=16,
        offset=0,
        width=2,
        count=3,
        kind="induction_like",
    )
    traits = {
        "base_const": {},
        "base_stride": {},
        "repeated_offsets": {},
        "repeated_offset_widths": {},
        "base_stride_widths": {},
        "induction_evidence": {},
        "stride_evidence": {
            ("induction_like", "ss", ("stack", "bp", -4), ("reg", 30), 16, 0, 2): evidence,
        },
        "member_evidence": {},
        "array_evidence": {},
    }

    profiles = _build_access_trait_evidence_profiles(traits)

    assert profiles[("reg", 30)].stride_evidence == (evidence,)
