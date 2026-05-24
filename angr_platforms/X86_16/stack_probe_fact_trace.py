from __future__ import annotations

from collections.abc import Mapping

STACK_PROBE_FACT_STAT_KEYS = (
    "summaries_attached",
    "stack_probe_summaries",
    "ss_stack_address_returns",
    "stack_arg_materializations",
    "stable_ss_lowering_replacements",
    "stable_ss_lowering_refusals",
    "callsite_count",
    "call_target_fact_count",
    "call_target_materialized_count",
    "call_arg_fact_count",
    "call_arg_materialized_count",
    "bp_slot_arg_value_normalized_count",
    "pointer_arg_materialized_count",
    "push_order_reversed_count",
    "consumed_outgoing_stack_placeholder_count",
    "stale_target_rejected_count",
    "known_prototype_arg_mismatch_count",
    "failure_count",
)


def ensure_stack_probe_fact_stats_8616(codegen) -> dict[str, int]:
    """Return the per-codegen stack-probe fact trace counters."""
    stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
    if not isinstance(stats, dict):
        stats = {key: 0 for key in STACK_PROBE_FACT_STAT_KEYS}
        codegen._inertia_stack_probe_fact_stats = stats
    for key in STACK_PROBE_FACT_STAT_KEYS:
        value = stats.get(key)
        if not isinstance(value, int):
            stats[key] = 0
    return stats


def _seen_tokens(codegen) -> set[tuple]:
    seen = getattr(codegen, "_inertia_stack_probe_fact_seen", None)
    if not isinstance(seen, set):
        seen = set()
        codegen._inertia_stack_probe_fact_seen = seen
    return seen


def record_callsite_summary_fact_8616(codegen, summary, *, node_id: int | None = None, attached: bool = False) -> None:
    """Count callsite facts once per summary identity without changing C output."""
    stats = ensure_stack_probe_fact_stats_8616(codegen)
    token = (
        "summary",
        node_id,
        getattr(summary, "callsite_addr", None),
        getattr(summary, "target_addr", None),
        getattr(summary, "return_addr", None),
    )
    seen = _seen_tokens(codegen)
    if attached and ("attached", token) not in seen:
        stats["summaries_attached"] += 1
        seen.add(("attached", token))
    if token in seen:
        return
    seen.add(token)
    if bool(getattr(summary, "stack_probe_helper", False)):
        stats["stack_probe_summaries"] += 1
        if (
            getattr(summary, "helper_return_state", None) == "stack_address"
            and getattr(summary, "helper_return_space", None) == "ss"
        ):
            stats["ss_stack_address_returns"] += 1


def record_callsite_summary_map_facts_8616(codegen, summary_map: Mapping | None) -> None:
    """Record already-attached summary facts for focused diagnostics."""
    if not isinstance(summary_map, Mapping):
        return
    for node_id, summary in summary_map.items():
        record_callsite_summary_fact_8616(codegen, summary, node_id=node_id if isinstance(node_id, int) else None)


def record_stack_arg_materialization_8616(codegen, count: int) -> None:
    """Count stack arguments converted into call arguments."""
    if count <= 0:
        return
    ensure_stack_probe_fact_stats_8616(codegen)["stack_arg_materializations"] += count


def record_stable_ss_lowering_replacement_8616(codegen) -> None:
    """Count a successful stable-SS lowering callback pass."""
    ensure_stack_probe_fact_stats_8616(codegen)["stable_ss_lowering_replacements"] += 1


def record_stable_ss_lowering_refusal_8616(codegen) -> None:
    """Count a lowering pass that saw typed SS facts but could not lower them."""
    ensure_stack_probe_fact_stats_8616(codegen)["stable_ss_lowering_refusals"] += 1


def format_stack_probe_fact_stats_8616(codegen) -> str | None:
    """Return a deterministic compact trace string for debug logs."""
    stats = getattr(codegen, "_inertia_stack_probe_fact_stats", None)
    if not isinstance(stats, dict):
        return None
    return " ".join(f"{key}={int(stats.get(key, 0) or 0)}" for key in STACK_PROBE_FACT_STAT_KEYS)
