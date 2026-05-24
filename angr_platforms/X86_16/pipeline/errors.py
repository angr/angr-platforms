from __future__ import annotations

"""Hard failure infrastructure for the Inertia pipeline.

AGENTS rule #3: Segmented memory must NOT be flattened.
AGENTS rule #9: Do not guess; fail explicitly instead.

PipelineHardError replaces silent fallback paths everywhere
in the pipeline with deterministic, actionable failures.
"""

__all__ = ["PipelineHardError"]


class PipelineHardError(Exception):
    """Fatal violation of AGENTS pipeline discipline.

    Raised when a layer cannot resolve a proven input correctly.
    Must never be caught silently — only handled at the top-level
    function decompiler to emit honest partial output.

    Replaces:
    - AliasFailure dataclass returns
    - fallback memory variable creation
    - silent 'continue' on unknown storage
    - uncollected validation treated as success
    """

    def __init__(self, message: str, *, layer: str = "", function_addr: int | None = None, details: object = None) -> None:
        super().__init__(message)
        self.layer = layer
        self.function_addr = function_addr
        self.details = details