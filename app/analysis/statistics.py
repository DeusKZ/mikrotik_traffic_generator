from __future__ import annotations

from collections import Counter

import numpy as np

from app.core.models import Flow


class StatisticsBuilder:
    def protocol_distribution(self, flows: list[Flow]) -> dict[str, int]:
        return dict(Counter(flow.protocol.value for flow in flows))

    def packet_size_histogram(self, flows: list[Flow], bins: int = 20) -> dict[str, list[float]]:
        all_sizes = [size for flow in flows for size in flow.packet_sizes]
        hist, edges = np.histogram(all_sizes if all_sizes else [0], bins=bins)
        return {"bins": edges.tolist(), "counts": hist.tolist()}

    def flow_duration_distribution(self, flows: list[Flow]) -> list[float]:
        return [flow.duration for flow in flows]

    def pps_distribution(self, flows: list[Flow]) -> list[float]:
        return [flow.pps for flow in flows]

    def summary(self, flows: list[Flow]) -> dict[str, float]:
        durations = self.flow_duration_distribution(flows)
        pps_values = self.pps_distribution(flows)
        return {
            "flow_count": float(len(flows)),
            "avg_duration": float(np.mean(durations)) if durations else 0.0,
            "avg_pps": float(np.mean(pps_values)) if pps_values else 0.0,
            "max_pps": float(np.max(pps_values)) if pps_values else 0.0,
        }
