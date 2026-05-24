from __future__ import annotations

"""Layer: Quality measurement (cross-cutting diagnostics).

Responsibility: measure decompilation quality with VEX/tmp leakage metrics.
Forbidden: semantic recovery, postprocess cleanup ownership."""

import re
from collections.abc import Mapping


__all__ = [
    "X86_16QualityMetrics",
    "measure_x86_16_codegen_quality_8616",
    "measure_x86_16_function_quality_8616",
    "format_x86_16_quality_report_8616",
]


class X86_16QualityMetrics:
    """Decompilation quality metrics for a single function."""

    __slots__ = (
        "function_name",
        "function_addr",
        "tmp_condition_count",
        "raw_flag_condition_count",
        "raw_ss_linear_expr_count",
        "asm_fallback_count",
        "validation_uncollected_count",
        "typed_condition_count",
        "named_local_count",
    )

    def __init__(
        self,
        *,
        function_name: str = "unknown",
        function_addr: int = 0,
        tmp_condition_count: int = 0,
        raw_flag_condition_count: int = 0,
        raw_ss_linear_expr_count: int = 0,
        asm_fallback_count: int = 0,
        validation_uncollected_count: int = 0,
        typed_condition_count: int = 0,
        named_local_count: int = 0,
    ) -> None:
        self.function_name = function_name
        self.function_addr = function_addr
        self.tmp_condition_count = tmp_condition_count
        self.raw_flag_condition_count = raw_flag_condition_count
        self.raw_ss_linear_expr_count = raw_ss_linear_expr_count
        self.asm_fallback_count = asm_fallback_count
        self.validation_uncollected_count = validation_uncollected_count
        self.typed_condition_count = typed_condition_count
        self.named_local_count = named_local_count

    def to_dict(self) -> dict[str, object]:
        return {
            "function_name": self.function_name,
            "function_addr": self.function_addr,
            "tmp_condition_count": self.tmp_condition_count,
            "raw_flag_condition_count": self.raw_flag_condition_count,
            "raw_ss_linear_expr_count": self.raw_ss_linear_expr_count,
            "asm_fallback_count": self.asm_fallback_count,
            "validation_uncollected_count": self.validation_uncollected_count,
            "typed_condition_count": self.typed_condition_count,
            "named_local_count": self.named_local_count,
        }

    @property
    def total_bad_patterns(self) -> int:
        return (
            self.tmp_condition_count
            + self.raw_flag_condition_count
            + self.raw_ss_linear_expr_count
            + self.asm_fallback_count
        )

    @property
    def quality_score(self) -> float:
        penalty = self.total_bad_patterns * 0.1 + self.validation_uncollected_count * 0.5
        penalty = min(penalty, 0.95)
        return round(1.0 - penalty, 3)


_TMP_CONDITION_RE = re.compile(r"tmp_\d+", re.IGNORECASE)
_RAW_FLAG_RE = re.compile(r"\b(flags|eflags)\b", re.IGNORECASE)
_RAW_SS_EXPR_RE = re.compile(r"\(\(ss\s*<<\s*4\)\s*\+", re.IGNORECASE)
_CMP_NE_RE = re.compile(r"CmpNE\(", re.IGNORECASE)
_CMP_EQ_RE = re.compile(r"CmpEQ\(", re.IGNORECASE)


def measure_x86_16_codegen_quality_8616(
    c_text: str,
    *,
    function_name: str = "unknown",
    function_addr: int = 0,
    asm_fallback: bool = False,
    validation_uncollected: bool = False,
) -> X86_16QualityMetrics:
    """Measure VEX/tmp leak metrics from generated C text."""
    tmp_condition_count = len(_TMP_CONDITION_RE.findall(c_text))
    raw_flag_condition_count = len(_RAW_FLAG_RE.findall(c_text))
    raw_ss_linear_expr_count = len(_RAW_SS_EXPR_RE.findall(c_text))
    asm_fallback_count = 1 if asm_fallback else 0
    typed_condition_count = len(_CMP_NE_RE.findall(c_text)) + len(_CMP_EQ_RE.findall(c_text))
    named_local_count = len(re.findall(r"\bvar_[0-9a-f]+\b", c_text, re.IGNORECASE))

    return X86_16QualityMetrics(
        function_name=function_name,
        function_addr=function_addr,
        tmp_condition_count=tmp_condition_count,
        raw_flag_condition_count=raw_flag_condition_count,
        raw_ss_linear_expr_count=raw_ss_linear_expr_count,
        asm_fallback_count=asm_fallback_count,
        validation_uncollected_count=1 if validation_uncollected else 0,
        typed_condition_count=typed_condition_count,
        named_local_count=named_local_count,
    )


def measure_x86_16_function_quality_8616(
    metrics_list: list[X86_16QualityMetrics],
) -> dict[str, object]:
    """Aggregate quality metrics across multiple functions."""
    if not metrics_list:
        return {
            "function_count": 0,
            "total_tmp_conditions": 0,
            "total_raw_flag_conditions": 0,
            "total_raw_ss_linear_exprs": 0,
            "total_asm_fallbacks": 0,
            "total_validation_uncollected": 0,
            "total_typed_conditions": 0,
            "total_named_locals": 0,
            "avg_quality_score": 0.0,
        }
    total = len(metrics_list)
    return {
        "function_count": total,
        "total_tmp_conditions": sum(m.tmp_condition_count for m in metrics_list),
        "total_raw_flag_conditions": sum(m.raw_flag_condition_count for m in metrics_list),
        "total_raw_ss_linear_exprs": sum(m.raw_ss_linear_expr_count for m in metrics_list),
        "total_asm_fallbacks": sum(m.asm_fallback_count for m in metrics_list),
        "total_validation_uncollected": sum(m.validation_uncollected_count for m in metrics_list),
        "total_typed_conditions": sum(m.typed_condition_count for m in metrics_list),
        "total_named_locals": sum(m.named_local_count for m in metrics_list),
        "avg_quality_score": round(sum(m.quality_score for m in metrics_list) / max(total, 1), 3),
    }


def format_x86_16_quality_report_8616(aggregate: Mapping[str, object]) -> str:
    """Format an aggregate quality report as a human-readable string."""
    total = int(aggregate.get("function_count", 0))
    lines: list[str] = [
        f"Quality Report ({total} functions)",
        "=" * 40,
        f"  tmp conditions:          {aggregate.get('total_tmp_conditions', 0)}",
        f"  raw flag conditions:     {aggregate.get('total_raw_flag_conditions', 0)}",
        f"  raw ss linear exprs:     {aggregate.get('total_raw_ss_linear_exprs', 0)}",
        f"  asm fallbacks:           {aggregate.get('total_asm_fallbacks', 0)}",
        f"  validation uncollected:  {aggregate.get('total_validation_uncollected', 0)}",
        f"  typed conditions:        {aggregate.get('total_typed_conditions', 0)}",
        f"  named locals:            {aggregate.get('total_named_locals', 0)}",
        f"  avg quality score:       {aggregate.get('avg_quality_score', 0.0)}",
    ]
    return "\n".join(lines)