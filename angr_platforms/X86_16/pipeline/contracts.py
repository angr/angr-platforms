from __future__ import annotations

"""Layer: Pipeline governance (runtime contracts).

Responsibility: enforce closed-loop evidence discipline at runtime.

AGENTS rule: facts produced but not consumed is a pipeline failure.
If ``classified > 0`` and ``materialized == 0``, raise ``PipelineHardError``.

This is NOT a soft diagnostic — it is a hard gate before codegen.

Typical pipeline trace:

    raw → normalized → classified → bound → materialized → verified

Materialization means the downstream representation used for code generation
has changed:
  - AIL expression replaced
  - SimVariable registered and used
  - C emission uses ``local_*``, ``arg_*``, or explicit condition

Creating ``StackVariableBinding`` or ``ConditionIR`` metadata is NOT
materialization.  ``binding_count > 0`` and ``materialized_count == 0``
is failure, not progress.

Do not add new recovery logic here.  This module only enforces contracts.
"""

from dataclasses import dataclass, field

from .errors import PipelineHardError

__all__ = [
    "SemanticLaneState",
    "assert_pipeline_contracts_8616",
]


@dataclass(slots=True)
class SemanticLaneState:
    """Closed-loop counter for one semantic lane (stack / condition).

    Counters record the pipeline trace:

        raw → normalized → classified → bound → materialized → verified
    """

    name: str = ""
    raw: int = 0
    normalized: int = 0
    classified: int = 0
    bound: int = 0
    materialized: int = 0
    verified: int = 0
    failures: int = 0

    def assert_closed_loop(self, *, layer: str = "") -> None:
        """Raise PipelineHardError if the lane is broken.

        Rules:
        - raw > 0 && normalized == 0 → HARD error (IR normalization failure)
        - bound > 0 && materialized == 0 → HARD error (bindings are not materialization)
        - classified > 0 && materialized == 0 → HARD error
        """
        if self.raw > 0 and self.normalized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.raw} raw accesses captured but 0 normalized "
                f"(classified={self.classified} bound={self.bound} "
                f"materialized={self.materialized})",
                layer=layer or "pipeline_contract",
            )

        if self.bound > 0 and self.materialized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.bound} bindings created but 0 materialized "
                f"(raw={self.raw} normalized={self.normalized} "
                f"classified={self.classified} failures={self.failures})",
                layer=layer or "pipeline_contract",
            )

        if self.classified > 0 and self.materialized == 0:
            raise PipelineHardError(
                f"{self.name}: {self.classified} facts classified but 0 materialized "
                f"(raw={self.raw} normalized={self.normalized} "
                f"bound={self.bound} failures={self.failures})",
                layer=layer or "pipeline_contract",
            )

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "raw": self.raw,
            "normalized": self.normalized,
            "classified": self.classified,
            "bound": self.bound,
            "materialized": self.materialized,
            "verified": self.verified,
            "failures": self.failures,
        }

    @property
    def is_closed(self) -> bool:
        """True if the lane has no un-materialized facts and all raw inputs were normalized."""
        if self.raw > 0 and self.normalized == 0:
            return False
        if self.classified > 0 and self.materialized == 0:
            return False
        if self.bound > 0 and self.materialized == 0:
            return False
        return True

    def summary_line(self) -> str:
        """Single-line summary for diagnostic output."""
        parts = [
            f"raw={self.raw}",
            f"norm={self.normalized}",
            f"clsf={self.classified}",
            f"bound={self.bound}",
            f"mat={self.materialized}",
            f"ver={self.verified}",
            f"fail={self.failures}",
        ]
        status = "CLOSED" if self.is_closed else "BROKEN"
        return f"{self.name}: [{status}] " + " ".join(parts)


def assert_pipeline_contracts_8616(codegen) -> None:
    """Hard gate: assert stack and condition lanes are closed before codegen.

    Call this after all lowering passes and before code emission.
    Raises PipelineHardError if any lane has un-materialized facts.
    """
    stack_lane = getattr(codegen, "_inertia_stack_lane", None)
    condition_lane = getattr(codegen, "_inertia_condition_lane", None)

    if stack_lane is not None:
        # Tiny thunk allowance:
        # Some 86_16 micro-stubs (e.g. 3-8 byte bridge thunks) can trip raw
        # stack-lane probes without producing meaningful normalized/classified
        # stack semantics. Keep the hard contract for all non-trivial
        # procedures, but avoid false-positive hard stops on these tiny stubs.
        cfunc = getattr(codegen, "cfunc", None)
        project = getattr(codegen, "project", None)
        func_size = None
        if project is not None and cfunc is not None:
            try:
                kb_func = project.kb.functions.function(addr=getattr(cfunc, "addr", None), create=False)
                if kb_func is not None:
                    size = getattr(kb_func, "size", None)
                    if isinstance(size, int) and size > 0:
                        func_size = size
            except Exception:
                func_size = None
        tiny_stack_stub = (
            isinstance(func_size, int)
            and func_size <= 8
            and int(getattr(stack_lane, "raw", 0) or 0) > 0
            and int(getattr(stack_lane, "normalized", 0) or 0) == 0
            and int(getattr(stack_lane, "classified", 0) or 0) == 0
            and int(getattr(stack_lane, "bound", 0) or 0) == 0
            and int(getattr(stack_lane, "materialized", 0) or 0) == 0
        )
        if not tiny_stack_stub:
            stack_lane.assert_closed_loop(layer="pipeline_contract:stack_lane")

    if condition_lane is not None:
        condition_lane.assert_closed_loop(layer="pipeline_contract:condition_lane")
