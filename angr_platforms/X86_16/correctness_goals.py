from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CorrectnessGoalSpec:
    code: str
    title: str
    priority: str
    status: str
    deterministic_goal: str
    owner_surfaces: tuple[str, ...]
    completion_signal: str


CORRECTNESS_GOALS: tuple[CorrectnessGoalSpec, ...] = (
    CorrectnessGoalSpec(
        code="C6.1",
        title="Keep COD source logic green on compare and runtime samples",
        priority="P0",
        status="landed",
        deterministic_goal=(
            "Keep the decompiler output aligned with the original COD C logic on compare-style and runtime sample probes."
        ),
        owner_surfaces=(
            "tests/test_x86_16_cod_samples.py",
            "validation_families",
            "tests/test_x86_16_compare_semantics.py",
            "tests/test_x86_16_runtime_samples.py",
        ),
        completion_signal="COD-source-backed compare and runtime regressions stay explicit, bounded, and green.",
    ),
    CorrectnessGoalSpec(
        code="C6.2",
        title="Keep sample matrix and 80286 verifier aligned to source C",
        priority="P0",
        status="landed",
        deterministic_goal=(
            "Keep the sample matrix and 80286 verifier consistent with the original COD source C logic and instruction behavior."
        ),
        owner_surfaces=(
            "tests/test_x86_16_cod_samples.py",
            "validation_families",
            "tests/test_x86_16_sample_matrix.py",
            "tests/test_x86_16_80286_verifier.py",
        ),
        completion_signal="Sample-matrix, COD-source anchors, and hardware-backed verification stay green together.",
    ),
    CorrectnessGoalSpec(
        code="C6.3",
        title="Keep calling-convention and return compatibility faithful to source C",
        priority="P0",
        status="landed",
        deterministic_goal=(
            "Keep call/return prototypes and decompiler return compatibility anchored to the original COD call surfaces and shared compatibility helpers."
        ),
        owner_surfaces=(
            "tests/test_x86_16_cod_samples.py",
            "calling_convention_compat",
            "decompiler_return_compat",
            "tests/test_x86_16_package_exports.py",
            "tests/test_x86_16_helper_modeling.py",
        ),
        completion_signal="Prototype and return-compatibility helpers preserve the same source-level call/return meaning as the COD originals.",
    ),
    CorrectnessGoalSpec(
        code="C6.4",
        title="Keep interrupt lowering correctness-driven and bounded by source C",
        priority="P1",
        status="landed",
        deterministic_goal=(
            "Keep interrupt-core semantics separate from DOS/BIOS/MS-C lowering and keep the source C wrapper logic visible as bounded debt."
        ),
        owner_surfaces=(
            "tests/test_x86_16_cod_samples.py",
            "interrupt_api_surface",
            "interrupt_core_surface",
            "interrupt_lowering_boundary",
            "analysis_helpers",
            "decompile",
        ),
        completion_signal="Interrupt lowering remains helper-backed, boundary-aware, and faithful to the COD source wrapper logic.",
    ),
)


def describe_x86_16_correctness_goals() -> tuple[tuple[str, str, str, str, tuple[str, ...], str], ...]:
    return tuple(
        (
            goal.code,
            goal.title,
            goal.priority,
            goal.status,
            goal.owner_surfaces,
            goal.completion_signal,
        )
        for goal in CORRECTNESS_GOALS
    )


def summarize_x86_16_correctness_goals() -> dict[str, object]:
    landed = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "landed")
    partial = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "partial")
    open_ = sum(1 for goal in CORRECTNESS_GOALS if goal.status == "open")
    strict_percent = round(landed / len(CORRECTNESS_GOALS) * 100, 2) if CORRECTNESS_GOALS else 0.0
    weighted_percent = round((landed + 0.5 * partial) / len(CORRECTNESS_GOALS) * 100, 2) if CORRECTNESS_GOALS else 0.0
    return {
        "total": len(CORRECTNESS_GOALS),
        "landed": landed,
        "partial": partial,
        "open": open_,
        "strict_percent": strict_percent,
        "weighted_percent": weighted_percent,
        "landed_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "landed"),
        "partial_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "partial"),
        "open_codes": tuple(goal.code for goal in CORRECTNESS_GOALS if goal.status == "open"),
    }


__all__ = [
    "CORRECTNESS_GOALS",
    "CorrectnessGoalSpec",
    "describe_x86_16_correctness_goals",
    "summarize_x86_16_correctness_goals",
]
