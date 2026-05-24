from __future__ import annotations

from .structuring_abnormal_loops import AbnormalLoopStructureAnalysis
from .structuring_analysis import RegionBasedStructuringPass, RegionType
from .structuring_grouped_graph_builder import build_grouped_region_graph


class GroupedRegionBasedStructuringPass(RegionBasedStructuringPass):
    def __call__(self, codegen) -> bool:
        if getattr(codegen, "cfunc", None) is None:
            return False

        try:
            graph, entry = self._build_region_graph(codegen)
            if graph is None or entry is None or len(graph.nodes) < 2:
                return False

            analysis = AbnormalLoopStructureAnalysis(graph)
            structured = analysis.structure()
            self.stats = analysis.stats

            cfunc = codegen.cfunc
            if not hasattr(cfunc, "_structuring_stats"):
                cfunc._structuring_stats = {}
            cfunc._structuring_stats["iterations"] = self.stats.iterations
            cfunc._structuring_stats["regions_reduced"] = self.stats.regions_reduced
            cfunc._structuring_stats["cycles_resolved"] = self.stats.cycles_resolved
            cfunc._structuring_stats["sequences_created"] = self.stats.sequences_created
            cfunc._structuring_stats["final_node_count"] = len(structured.nodes)

            structured_regions = []
            abnormal_loop_regions = []
            for region in structured.nodes:
                if region.region_type != RegionType.Linear:
                    structured_regions.append(
                        {
                            "addr": region.block_addr,
                            "type": region.region_type.value,
                            "metadata_keys": list(region.metadata.keys()),
                        }
                    )
                if "abnormal_loop_plan" in region.metadata:
                    abnormal_loop_regions.append(region.metadata["abnormal_loop_plan"])
            cfunc._structuring_stats["structured_regions"] = structured_regions
            cfunc._structuring_stats["abnormal_loop_regions"] = abnormal_loop_regions

            return (
                self.stats.regions_reduced > 0
                or self.stats.cycles_resolved > 0
                or self.stats.sequences_created > 0
            )
        except Exception:
            return False

    def _build_region_graph(self, codegen) -> tuple:
        result = build_grouped_region_graph(codegen)
        return result.graph_result.graph, result.graph_result.entry


def apply_grouped_region_based_structuring(codegen) -> bool:
    pass_instance = GroupedRegionBasedStructuringPass()
    return pass_instance(codegen)


def describe_x86_16_grouped_structuring_pass_surface() -> dict[str, object]:
    return {
        "pass_class": "GroupedRegionBasedStructuringPass",
        "graph_builder": "build_grouped_region_graph",
        "analysis_class": "AbnormalLoopStructureAnalysis",
        "purpose": "Feed grouped region graphs into the real region-based structuring driver.",
    }


__all__ = [
    "GroupedRegionBasedStructuringPass",
    "apply_grouped_region_based_structuring",
    "describe_x86_16_grouped_structuring_pass_surface",
]
