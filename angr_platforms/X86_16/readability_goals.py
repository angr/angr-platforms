from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class ReadabilityClusterSpec:
    name: str
    pattern: str
    purpose: str
    owner: str


@dataclass(frozen=True)
class ReadabilityGoalSpec:
    step: str
    title: str
    priority: str
    deterministic_goal: str
    target_clusters: tuple[str, ...]
    owner_surfaces: tuple[str, ...]
    completion_signal: str


READABILITY_CLUSTER_SPECS: tuple[ReadabilityClusterSpec, ...] = (
    ReadabilityClusterSpec(
        name="byte_pair_arithmetic",
        pattern=r"(<<\s*8|\*\s*(?:0x)?100\b|0x100\b)",
        purpose="Byte-pair arithmetic still survives in the text instead of widening earlier.",
        owner="alias_widening",
    ),
    ReadabilityClusterSpec(
        name="split_segmented_word_accesses",
        pattern=r"(\b(?:es|ds|ss)\s*:\s*|\bsegment(ed)?\b|\bfar\b)",
        purpose="Segmented loads/stores still show up as split or raw segment accesses.",
        owner="addressing_alias",
    ),
    ReadabilityClusterSpec(
        name="fake_locals_and_stack_noise",
        pattern=r"(local_|var_|stack_|bp\+|sp\+)",
        purpose="Stack material is still rendered as noisy locals or raw stack offsets.",
        owner="stack_alias",
    ),
    ReadabilityClusterSpec(
        name="weak_helper_signatures",
        pattern=r"(\bsub_[0-9a-f]+\b|\bhelper_\w+\b|\bunknown\b)",
        purpose="Helpers still look synthetic or weakly named.",
        owner="interrupt_api",
    ),
    ReadabilityClusterSpec(
        name="boolean_noise",
        pattern=r"(&&|\|\||!=\s*0|==\s*0|!\s*\()",
        purpose="Boolean expressions still need postprocess cleanup.",
        owner="projection_cleanup",
    ),
    ReadabilityClusterSpec(
        name="unresolved_member_or_array_opportunities",
        pattern=r"(\+\s*0x[0-9a-f]+|\+\s*\d+|\[[^\]]+\])",
        purpose="Member and array opportunities are still visible as raw offsets or indexing noise.",
        owner="traits_types_objects",
    ),
)


READABILITY_GOALS: tuple[ReadabilityGoalSpec, ...] = (
    ReadabilityGoalSpec(
        step="4.1",
        title="Fix the top ugly clusters, not isolated outputs",
        priority="P1",
        deterministic_goal=(
            "Rank repeated ugly forms from scan output, then chip away at the highest-frequency clusters "
            "instead of single showcase functions."
        ),
        target_clusters=(
            "byte_pair_arithmetic",
            "split_segmented_word_accesses",
            "fake_locals_and_stack_noise",
            "weak_helper_signatures",
            "boolean_noise",
            "unresolved_member_or_array_opportunities",
        ),
        owner_surfaces=(
            "corpus_scan.top_ugly_clusters",
            "corpus_scan.family_ownership.top_ugly_clusters",
            "milestone_report.readability_backlog",
        ),
        completion_signal=(
            "Milestone reports always show stable ranked clusters, and each readability sprint starts from the top cluster counts."
        ),
    ),
    ReadabilityGoalSpec(
        step="4.2",
        title="Spend the first major readability budget on alias and widening",
        priority="P0",
        deterministic_goal=(
            "Move byte-pair, projection, and split-segment cleanup onto alias and widening proof surfaces, "
            "then keep late rewrite from re-solving storage identity."
        ),
        target_clusters=(
            "byte_pair_arithmetic",
            "split_segmented_word_accesses",
            "fake_locals_and_stack_noise",
        ),
        owner_surfaces=(
            "alias_api",
            "widening_pipeline",
            "projection_cleanup_rules",
            "source_backed_rewrite_debt",
        ),
        completion_signal=(
            "Several old local coalescers become thin wrappers and the remaining cleanup work consumes shared alias/widening facts."
        ),
    ),
    ReadabilityGoalSpec(
        step="4.3",
        title="Only then spend on traits, types, and objects",
        priority="P1",
        deterministic_goal=(
            "Let trait evidence drive typed object recovery only after alias and widening are stable, "
            "so field, array, global, and stack-object wins stay evidence-driven."
        ),
        target_clusters=(
            "fake_locals_and_stack_noise",
            "weak_helper_signatures",
            "unresolved_member_or_array_opportunities",
        ),
        owner_surfaces=(
            "recovery_layers",
            "validation_families",
            "readability_set",
            "readability_tiers",
        ),
        completion_signal=(
            "Object-like output increases without a matching rise in hallucinated structs or arrays."
        ),
    ),
)


def describe_x86_16_readability_goals() -> tuple[tuple[str, str, str, tuple[str, ...], tuple[str, ...], str], ...]:
    return tuple(
        (
            goal.step,
            goal.title,
            goal.deterministic_goal,
            goal.target_clusters,
            goal.owner_surfaces,
            goal.completion_signal,
        )
        for goal in READABILITY_GOALS
    )


def classify_readability_cluster(text: str | None) -> tuple[str | None, str | None]:
    if not text:
        return None, None
    for spec in READABILITY_CLUSTER_SPECS:
        if re.search(spec.pattern, text, flags=re.IGNORECASE):
            return spec.name, spec.purpose
    return None, None


def summarize_readability_goals(
    top_ugly_clusters: list[dict[str, object]],
    readability_clusters: list[dict[str, object]],
    family_ownership: Mapping[str, object],
) -> tuple[dict[str, object], ...]:
    cluster_counts = {
        str(item.get("cluster")): int(item.get("count", 0) or 0)
        for item in (readability_clusters or top_ugly_clusters)
        if item.get("cluster") is not None
    }
    family_clusters = {
        (str(item.get("cluster")), str(item.get("family"))): int(item.get("count", 0) or 0)
        for item in family_ownership.get("top_ugly_clusters", [])  # type: ignore[index]
        if isinstance(item, dict) and item.get("cluster") is not None and item.get("family") is not None
    }
    summaries: list[dict[str, object]] = []
    for goal in READABILITY_GOALS:
        observed_cluster_count = sum(cluster_counts.get(cluster, 0) for cluster in goal.target_clusters)
        observed_family_count = sum(
            count
            for cluster in goal.target_clusters
            for (family_cluster, _family), count in family_clusters.items()
            if family_cluster == cluster
        )
        summaries.append(
            {
                "step": goal.step,
                "title": goal.title,
                "priority": goal.priority,
                "deterministic_goal": goal.deterministic_goal,
                "target_clusters": goal.target_clusters,
                "owner_surfaces": goal.owner_surfaces,
                "completion_signal": goal.completion_signal,
                "observed_cluster_count": observed_cluster_count,
                "observed_family_count": observed_family_count,
            }
        )
    return tuple(summaries)


def rank_readability_goal_queue(
    goal_summary: tuple[dict[str, object], ...] | list[dict[str, object]],
) -> tuple[dict[str, object], ...]:
    ordered = sorted(
        goal_summary,
        key=lambda item: (
            -int(item.get("observed_cluster_count", 0) or 0),
            -int(item.get("observed_family_count", 0) or 0),
            str(item.get("step", "")),
        ),
    )
    queue: list[dict[str, object]] = []
    for rank, item in enumerate(ordered, start=1):
        queue.append(
            {
                **item,
                "rank": rank,
                "is_next_focus": rank == 1,
            }
        )
    return tuple(queue)


def summarize_readability_focus(
    top_ugly_clusters: list[dict[str, object]],
    readability_clusters: list[dict[str, object]],
    family_ownership: Mapping[str, object],
) -> dict[str, object]:
    goal_summary = summarize_readability_goals(top_ugly_clusters, readability_clusters, family_ownership)
    goal_queue = rank_readability_goal_queue(goal_summary)
    next_goal = goal_queue[0] if goal_queue else None
    return {
        "goal_queue": goal_queue,
        "next_goal": next_goal,
        "top_ugly_clusters": tuple(top_ugly_clusters),
        "readability_clusters": tuple(readability_clusters),
        "family_ownership": dict(family_ownership),
    }


__all__ = [
    "READABILITY_CLUSTER_SPECS",
    "READABILITY_GOALS",
    "ReadabilityClusterSpec",
    "ReadabilityGoalSpec",
    "classify_readability_cluster",
    "describe_x86_16_readability_goals",
    "rank_readability_goal_queue",
    "summarize_readability_focus",
    "summarize_readability_goals",
]
