from __future__ import annotations

from angr_platforms.X86_16.lst_extract import LSTMetadata
from inertia_decompiler.non_optimized_fallback import sidecar_verdict_closes_non_optimized_lane
from inertia_decompiler.sidecar_cache import _maybe_rebase_stale_absolute_metadata
from inertia_decompiler.slice_recovery import BoundedSliceVerdict


def test_sidecar_verdict_keeps_non_optimized_lane_open_for_repeated_decompile_empty() -> None:
    verdict = BoundedSliceVerdict(
        stage="decompile",
        stop_family="empty",
        can_widen_locally=False,
        can_retry_with_fresh_project=False,
    )

    assert sidecar_verdict_closes_non_optimized_lane(verdict) is False


def test_sidecar_verdict_closes_non_optimized_lane_for_repeated_recover_timeout() -> None:
    verdict = BoundedSliceVerdict(
        stage="recover",
        stop_family="timeout",
        can_widen_locally=False,
        can_retry_with_fresh_project=True,
    )

    assert sidecar_verdict_closes_non_optimized_lane(verdict) is True


def test_sidecar_verdict_does_not_close_lane_for_build_or_recover_errors() -> None:
    assert (
        sidecar_verdict_closes_non_optimized_lane(
            BoundedSliceVerdict(
                stage="build",
                stop_family="error",
                can_widen_locally=False,
                can_retry_with_fresh_project=True,
            )
        )
        is False
    )
    assert (
        sidecar_verdict_closes_non_optimized_lane(
            BoundedSliceVerdict(
                stage="recover",
                stop_family="error",
                can_widen_locally=False,
                can_retry_with_fresh_project=True,
            )
        )
        is False
    )


def test_rebase_stale_absolute_cod_metadata_to_linked_base() -> None:
    metadata = LSTMetadata(
        data_labels={0x200: "data"},
        code_labels={0x9D8: "PercolateUp", 0xF28: "Sleep"},
        code_ranges={0x9D8: (0x9D8, 0xA51), 0xF28: (0xF28, 0xF63)},
        signature_code_addrs=frozenset({0x9D8}),
        absolute_addrs=True,
        source_format="cod_listing+flair_pat",
        cod_proc_kinds={0x9D8: "NEAR"},
    )

    class _MainObject:
        linked_base = 0x10000

    class _Loader:
        main_object = _MainObject()

    class _Project:
        loader = _Loader()
        entry = 0x10F9A

    rebased = _maybe_rebase_stale_absolute_metadata(metadata, _Project())

    assert rebased.code_labels[0x109D8] == "PercolateUp"
    assert rebased.code_labels[0x10F28] == "Sleep"
    assert rebased.code_ranges[0x109D8] == (0x109D8, 0x10A51)
    assert 0x109D8 in rebased.signature_code_addrs
