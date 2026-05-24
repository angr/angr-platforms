from __future__ import annotations

from types import SimpleNamespace

from inertia_decompiler.cli_access_profiles import (
    AccessTraitEvidenceProfile,
    AccessTraitStrideEvidence,
    infer_induction_summary,
)

from angr_platforms.X86_16.arch_86_16 import Arch86_16
from angr_platforms.X86_16.decompiler_structuring_stage import (
    DECOMPILER_STRUCTURING_PASSES,
    _induction_summary_artifact_8616,
)


def test_infer_induction_summary_records_direction_and_bound_candidate():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("reg", 30),
                stride=-2,
                offset=6,
                width=2,
                count=3,
                kind="induction_like",
            ),
        ),
    )

    summary = infer_induction_summary(profile)

    assert summary is not None
    assert summary.direction == "decrement"
    assert summary.bound_candidate == 6
    assert summary.stride == -2


def test_infer_induction_summary_accepts_mixed_offsets_for_same_induction_variable():
    profile = AccessTraitEvidenceProfile(
        induction_evidence=(
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("stack", "bp", -2, 0x4010),
                stride=2,
                offset=0,
                width=2,
                count=2,
                kind="induction_like",
            ),
            AccessTraitStrideEvidence(
                segment="ss",
                base_key=("stack", "bp", -4),
                index_key=("stack", "bp", -2, 0x4010),
                stride=2,
                offset=4,
                width=2,
                count=3,
                kind="induction_like",
            ),
        ),
    )

    summary = infer_induction_summary(profile)

    assert summary is not None
    assert summary.index_key == ("stack", "bp", -2, 0x4010)
    assert summary.stride == 2
    assert summary.bound_candidate == 4


def test_structuring_stage_collects_induction_summaries_on_codegen():
    reg_offset = Arch86_16().registers["si"][0]
    project = SimpleNamespace(
        _inertia_access_traits={
            0x4010: {
                "base_const": {},
                "base_stride": {},
                "repeated_offsets": {},
                "repeated_offset_widths": {},
                "base_stride_widths": {},
                "member_evidence": {},
                "array_evidence": {},
                "induction_evidence": {
                    ("induction_like", "ss", ("stack", "bp", -4), ("reg", reg_offset), 2, 4, 2): AccessTraitStrideEvidence(
                        segment="ss",
                        base_key=("stack", "bp", -4),
                        index_key=("reg", reg_offset),
                        stride=2,
                        offset=4,
                        width=2,
                        count=3,
                        kind="induction_like",
                    )
                },
                "stride_evidence": {},
            }
        }
    )
    codegen = SimpleNamespace(
        project=project,
        cfunc=SimpleNamespace(addr=0x4010),
    )

    changed = _induction_summary_artifact_8616(codegen)

    assert changed is False
    assert len(codegen._inertia_induction_summaries) == 1
    assert codegen._inertia_induction_summaries[0].direction == "increment"
    assert codegen._inertia_induction_summaries[0].bound_candidate == 4


def test_structuring_stage_registers_induction_summary_pass_before_codegen():
    names = [spec.name for spec in DECOMPILER_STRUCTURING_PASSES]

    assert "_induction_summary_artifact_8616" in names
    assert names.index("_induction_summary_artifact_8616") < names.index("_structuring_codegen_8616")
