"""
Region-based control-flow structuring algorithm.

This module implements the core control-flow analysis that converts a region graph
into structured control-flow patterns (sequence, if-then-else, loops, etc).

The main algorithm operates iteratively:
1. Build a region graph from the CFG
2. Compute dominator relationships
3. Iteratively match and merge regions into structured patterns
4. Apply refinement strategies when no progress is made
5. Post-process to refine high-level constructs (loops, switches, etc)

Inspired by:
  - Reko's StructureAnalysis.cs
  - "Native x86 Decompilation using Semantics-Preserving Structural Analysis 
     and Iterative Control-Flow Structuring"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Callable, Optional

from .structuring_loops import (
    LoopExitClassification,
    NaturalLoopInfo,
    compute_loop_body,
    compute_loop_confidence,
    detect_natural_loop,
    is_well_structured_multi_exit,
)
from .structuring_graph_builder import build_region_graph
from .structuring_sequences import merge_would_hide_cycle, sequence_merge_is_safe
from .structuring_region import (
    DominatorInfo,
    Region,
    RegionGraph,
    RegionType,
    compute_dominators,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


@dataclass
class StructuringStats:
    """Statistics about the structuring process."""

    iterations: int = 0
    regions_reduced: int = 0
    cycles_resolved: int = 0
    sequences_created: int = 0
    max_iterations_reached: bool = False
    had_unstructured_gotos: bool = False


class StructureAnalysis:
    """
    Main control-flow structuring algorithm.

    This class takes a region graph and iteratively refines it into structured
    control-flow patterns through pattern matching and selective refinement.
    """

    # Maximum iterations before giving up (matches Reko)
    MAX_ITERATIONS = 1000

    def __init__(
        self,
        graph: RegionGraph,
        event_listener: Optional[Callable[[str], None]] = None,
        max_iterations: int = MAX_ITERATIONS,
    ):
        """
        Initialize the structuring analyzer.

        Args:
            graph: The region graph to structure
            event_listener: Optional callback for diagnostic messages
            max_iterations: Maximum iterations before stopping
        """
        self.graph = graph
        self.event_listener = event_listener or (lambda msg: None)
        self.max_iterations = max_iterations
        self.dominators: Optional[DominatorInfo] = None
        self.stats = StructuringStats()
        self.unresolved_cycles: list[tuple[Region, set[Region]]] = []
        self.unresolved_switches: list[Region] = []

    def structure(self) -> RegionGraph:
        """
        Perform control-flow structuring on the region graph.

        Returns:
            The refined region graph
        """
        return self._execute()

    def _execute(self) -> RegionGraph:
        """
        Core structuring algorithm.

        Iteratively:
        1. Recompute dominators
        2. Visit regions in post-order
        3. Try to match acyclic patterns
        4. Try to match cyclic patterns
        5. If no progress, apply refinement strategies
        6. Repeat until graph converges to a single region or max iterations
        """
        iterations = 0

        while True:
            iterations += 1
            self.stats.iterations = iterations

            # Check cancellation
            self.event_listener(f"Structuring iteration {iterations}")

            # Check iteration limit
            if iterations > self.max_iterations:
                logger.warning(
                    "Structure analysis stopped due to iteration limit (%d). "
                    "Control flow may not be fully structured.",
                    self.max_iterations,
                )
                self.stats.max_iterations_reached = True
                break

            # Recompute dominators for this iteration
            self.dominators = compute_dominators(self.graph)

            # Track progress
            old_node_count = len(self.graph.nodes)

            # Reset unresolved lists for this iteration
            self.unresolved_cycles.clear()
            self.unresolved_switches.clear()

            # Visit regions in post-order
            post_order = self.graph.iter_postorder()

            for region in post_order:
                # Try to reduce acyclic regions
                reduced = self._reduce_acyclic(region)

                # If no acyclic reduction, try cyclic patterns
                if not reduced and self._is_cyclic(region):
                    reduced = self._reduce_cyclic(region)

            # Check for progress
            new_node_count = len(self.graph.nodes)
            if new_node_count == old_node_count and new_node_count > 1:
                # No progress this round - try refinement strategies
                # But only if there are unresolved regions to process
                if self.unresolved_cycles or self.unresolved_switches:
                    self._process_unresolved_regions()
                else:
                    # No unresolved regions and no progress - we're stuck
                    # This is normal for well-structured CFGs that can't be fully reduced
                    logger.debug(
                        "No progress and no unresolved regions, stopping at %d nodes",
                        new_node_count,
                    )
                    break

            # Check convergence
            if len(self.graph.nodes) <= 1:
                break

        return self.graph

    def _reduce_acyclic(self, region: Region) -> bool:
        """
        Try to match and reduce acyclic patterns.

        Acyclic patterns include:
        - Sequence (merge two linear regions)
        - If-then (merge condition with single branch)
        - If-then-else (merge condition with two branches)
        - If-cascade-to-switch (merge 3+ conditions on same expression)

        Args:
            region: Region to attempt to reduce

        Returns:
            True if a reduction occurred, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Try sequence first (linear merge)
        if self._try_sequence(region):
            self.stats.sequences_created += 1
            return True

        # Try switch pattern detection (before if-then patterns)
        if self._try_if_switch_cascade(region):
            self.stats.regions_reduced += 1
            return True

        # Try if-then pattern
        if self._try_if_then(region):
            self.stats.regions_reduced += 1
            return True

        # Try if-then-else pattern
        if self._try_if_then_else(region):
            self.stats.regions_reduced += 1
            return True

        return False

    def _reduce_cyclic(self, region: Region) -> bool:
        """
        Try to match and reduce cyclic patterns.

        Cyclic patterns are loops with special structure.

        Args:
            region: Region to attempt to reduce

        Returns:
            True if a reduction occurred, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Try to detect and reduce natural loop
        if self._try_natural_loop(region):
            self.stats.cycles_resolved += 1
            return True

        return False

    def _try_natural_loop(self, region: Region) -> bool:
        """
        Try to match and reduce a natural loop pattern.

        Args:
            region: Candidate loop header region

        Returns:
            True if loop pattern matched and merged, False otherwise
        """
        loop_info = self._detect_natural_loop(region)
        if not loop_info:
            return False

        # If confidence is too low, don't merge yet - keep as unresolved
        if loop_info.confidence < 0.6:
            self.unresolved_cycles.append((region, loop_info.body_regions))
            return False

        # Merge all body regions into the header region
        try:
            for body_region in loop_info.body_regions:
                if body_region != region and body_region in self.graph.nodes:
                    self.graph.merge_regions(body_region, region, transfer_edges="both")

            # Mark as loop region
            region.region_type = RegionType.Loop
            region.metadata["loop_info"] = loop_info

            self.stats.regions_reduced += 1
            return True
        except Exception as e:
            logger.debug(f"Failed to merge natural loop regions: {e}")
            return False

    def _try_sequence(self, region: Region) -> bool:
        """
        Try to merge region into a sequence with its predecessor or successor.

        A sequence is two regions where one flows directly to the other.

        Args:
            region: Candidate region for sequence formation

        Returns:
            True if merge occurred, False otherwise
        """
        # Look for a single successor
        succs = self.graph.successors(region)
        if len(succs) == 1:
            succ = succs[0]
            if sequence_merge_is_safe(self.graph, self.dominators, region, succ):
                self.graph.merge_regions(succ, region, transfer_edges="succ")
                return True

        return False

    def _try_if_switch_cascade(self, region: Region) -> bool:
        """
        Try to detect and reduce an if-cascade pattern as a switch statement.

        An if-cascade is a sequence of if-else regions comparing the same
        expression against different constants. When 3+ branches are detected,
        this is a strong candidate for a switch statement.

        Args:
            region: Candidate region (typically a condition region)

        Returns:
            True if switch pattern was detected and region marked, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Skip if already marked as switch
        if region.region_type == RegionType.IncSwitch:
            return False

        # Check if this region has multiple successors (branch point)
        succs = self.graph.successors(region)
        if len(succs) < 3:
            return False  # Need at least 3 branches for a switch candidate

        # Mark as switch region - this indicates potential for switch statement
        # Full switch code generation happens in Phase 1.3
        region.region_type = RegionType.IncSwitch
        region.metadata["switch_candidates"] = list(succs)
        self.unresolved_switches.append(region)
        logger.debug(f"Marked region {region} as switch candidate with {len(succs)} branches")

        return True  # Count as processed since we marked it

    def _try_if_then(self, region: Region) -> bool:
        """
        Try to form an if-then pattern.

        If-then is: a condition region with exactly two successors where one
        is a straightforward branch and the other is a fall-through that only
        this region branches to.

        Args:
            region: Candidate condition region

        Returns:
            True if pattern found and merged, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Don't process if already marked as switch candidate
        if region.region_type == RegionType.IncSwitch:
            return False
        if self._is_cyclic(region):
            return False

        succs = self.graph.successors(region)
        if len(succs) != 2:
            return False

        # Check if either successor has only this region as predecessor
        # (meaning it's a dedicated then-block)
        for i, succ in enumerate(succs):
            preds = self.graph.predecessors(succ)
            if len(preds) == 1 and succ in preds[0].successors:
                if merge_would_hide_cycle(self.graph, self.dominators, region, succ):
                    continue
                # This is a dedicated branch - merge it into region
                self.graph.merge_regions(succ, region, transfer_edges="succ")
                # Update region type to reflect it's now a condition structure
                if region.region_type == RegionType.Linear:
                    region.region_type = RegionType.Condition
                return True

        return False

    def _try_if_then_else(self, region: Region) -> bool:
        """
        Try to form an if-then-else pattern.

        If-then-else is: a condition region with exactly two branches that
        can be merged together as a complete if-then-else structure.

        Conservative: don't merge if the region itself is cyclic (has back-edges),
        to preserve loop detection.

        Args:
            region: Candidate condition region

        Returns:
            True if pattern found and merged, False otherwise
        """
        if region not in self.graph.nodes:
            return False

        # Don't process if already marked as switch candidate
        if region.region_type == RegionType.IncSwitch:
            return False

        succs = self.graph.successors(region)
        if len(succs) != 2:
            return False

        # Don't merge if this region is cyclic (has back-edges to it)
        # This preserves the ability to detect loops
        if self._is_cyclic(region):
            return False

        # Try to merge both branches into the condition region
        # This creates a complete if-then-else structure
        branch1, branch2 = succs
        if merge_would_hide_cycle(self.graph, self.dominators, region, branch1):
            return False
        if merge_would_hide_cycle(self.graph, self.dominators, region, branch2):
            return False

        # Merge both branches into region
        try:
            # Merge first branch
            if branch1 in self.graph.nodes:
                self.graph.merge_regions(branch1, region, transfer_edges="succ")

            # Merge second branch (if still present after first merge)
            if branch2 in self.graph.nodes and branch2 != region:
                self.graph.merge_regions(branch2, region, transfer_edges="succ")

            # Mark region as a condition structure
            region.region_type = RegionType.Condition
            return True
        except Exception as e:
            logger.debug(f"Failed to merge if-then-else branches: {e}")
            return False

    def _is_cyclic(self, region: Region) -> bool:
        """
        Check if a region is part of a cycle (back edge exists).

        A region is cyclic if any of its predecessors is dominated by it.

        Args:
            region: Region to check

        Returns:
            True if region is cyclic, False otherwise
        """
        if self.dominators is None:
            return False

        preds = self.graph.predecessors(region)
        for pred in preds:
            if self.dominators.strictly_dominates(region, pred):
                return True

        return False

    def _detect_natural_loop(self, region: Region) -> Optional[NaturalLoopInfo]:
        if self.dominators is None:
            self.dominators = compute_dominators(self.graph)
        return detect_natural_loop(
            self.graph,
            self.dominators,
            region,
        )

    def _compute_loop_body(self, header: Region, back_edges: list[Region]) -> set[Region]:
        if self.dominators is None:
            return set()
        return compute_loop_body(self.graph, self.dominators, header, back_edges)

    def _is_well_structured_multi_exit(
        self, body_regions: set[Region], exit_edges: list[tuple[Region, Region]]
    ) -> bool:
        return is_well_structured_multi_exit(body_regions, exit_edges)

    def _compute_loop_confidence(
        self,
        header: Region,
        back_edges: list[Region],
        body_regions: set[Region],
        exit_edges: list[tuple[Region, Region]],
        is_reducible: bool,
    ) -> float:
        return compute_loop_confidence(
            header,
            back_edges,
            body_regions,
            exit_edges,
            is_reducible,
        )

    def _process_unresolved_regions(self) -> None:
        """
        Apply refinement strategies for unstructured regions.

        When the main algorithm makes no progress, we apply last-resort
        refinement strategies to ensure forward progress:
        - Convert unresolved cycles to explicit loop regions
        - Convert remaining multi-exit regions to explicit gotos
        """
        if not self.unresolved_cycles and not self.unresolved_switches:
            # No unresolved regions to process - fall back to goto refinement
            self._refine_to_gotos()
            return

        # Process unresolved cycles (low confidence)
        for region, cycle_regions in self.unresolved_cycles:
            # Mark as loop but emit goto fallback for exits
            region.region_type = RegionType.Loop
            
            # Find exit edges and store for goto emission
            for body_region in cycle_regions:
                if body_region in self.graph.nodes:
                    for succ in self.graph.successors(body_region):
                        if succ not in cycle_regions and succ != region:
                            # Store for potential goto emission
                            exits = region.metadata.get("unstructured_exits", [])
                            exits.append((body_region, succ))
                            region.metadata["unstructured_exits"] = exits
            
            self.stats.cycles_resolved += 1

        # Process unresolved switches
        for region in self.unresolved_switches:
            region.region_type = RegionType.IncSwitch

    def _refine_to_gotos(self) -> None:
        """
        Last-resort refinement: convert unstructured regions to explicit gotos.

        When no structuring pattern matches, we create explicit goto metadata
        to preserve the control flow while admitting we can't structure it.
        """
        # Find all regions with multiple successors that haven't been reduced
        unstructured = [
            r
            for r in self.graph.nodes
            if r.region_type == RegionType.Linear and len(self.graph.successors(r)) > 1
        ]

        for region in unstructured:
            # Create labeled exits for each successor
            for i, succ in enumerate(self.graph.successors(region)):
                label = f"__unstructured_{region.region_id:x}_{i}"
                exits = region.metadata.get("goto_exits", [])
                exits.append((succ, label))
                region.metadata["goto_exits"] = exits

            self.stats.had_unstructured_gotos = True

        if unstructured:
            logger.debug(
                f"Applied goto refinement for {len(unstructured)} unstructured regions"
            )
        else:
            logger.debug("No unstructured regions to refine to gotos")


class RegionBasedStructuringPass:
    """
    A decompiler pass that applies region-based structuring to codegen.

    This is the interface between the decompiler pass framework and the
    structuring algorithm.
    """

    def __init__(self):
        """Initialize the pass."""
        self.stats = StructuringStats()

    def __call__(self, codegen) -> bool:
        """
        Apply region-based structuring to codegen.

        Args:
            codegen: The codegen object to structure

        Returns:
            True if changes were made, False otherwise
        """
        if getattr(codegen, "cfunc", None) is None:
            return False

        try:
            # Build region graph from the decompiler's AIL/Clinic graph
            graph, entry = self._build_region_graph(codegen)
            if graph is None or entry is None or len(graph.nodes) < 2:
                # Nothing to structure
                return False

            # Run StructureAnalysis
            analysis = StructureAnalysis(graph)
            structured = analysis.structure()
            self.stats = analysis.stats

            # Record structuring stats on cfunc metadata
            cfunc = codegen.cfunc
            if not hasattr(cfunc, "_structuring_stats"):
                cfunc._structuring_stats = {}
            cfunc._structuring_stats["iterations"] = self.stats.iterations
            cfunc._structuring_stats["regions_reduced"] = self.stats.regions_reduced
            cfunc._structuring_stats["cycles_resolved"] = self.stats.cycles_resolved
            cfunc._structuring_stats["sequences_created"] = self.stats.sequences_created
            cfunc._structuring_stats["final_node_count"] = len(structured.nodes)

            # Record structured region types on cfunc
            structured_regions = []
            for region in structured.nodes:
                if region.region_type != RegionType.Linear:
                    structured_regions.append({
                        "addr": region.block_addr,
                        "type": region.region_type.value,
                        "metadata_keys": list(region.metadata.keys()),
                    })
            cfunc._structuring_stats["structured_regions"] = structured_regions

            # Return True if any structuring occurred
            changed = (
                self.stats.regions_reduced > 0
                or self.stats.cycles_resolved > 0
                or self.stats.sequences_created > 0
            )
            return changed
        except Exception as ex:
            logger.warning("Region-based structuring pass failed: %s", ex)
            return False

    def _build_region_graph(self, codegen) -> tuple:
        result = build_region_graph(codegen)
        return result.graph, result.entry


def apply_region_based_structuring(codegen) -> bool:
    """
    Apply region-based structuring pass to codegen.

    This is the entry point for the decompiler framework.

    Args:
        codegen: The codegen object to structure

    Returns:
        True if changes were made, False otherwise
    """
    pass_instance = RegionBasedStructuringPass()
    return pass_instance(codegen)
