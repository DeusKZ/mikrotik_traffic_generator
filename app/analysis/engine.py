from __future__ import annotations

from app.analysis.clustering import FlowClusterer
from app.analysis.patterns import TrafficPatternDetector
from app.analysis.statistics import StatisticsBuilder
from app.core.models import AnalysisResult, Flow


class AnalysisEngine:
    def __init__(self) -> None:
        self.pattern_detector = TrafficPatternDetector()
        self.clusterer = FlowClusterer()
        self.stats = StatisticsBuilder()

    def analyze(self, flows: list[Flow]) -> AnalysisResult:
        for flow in flows:
            flow.pattern = self.pattern_detector.detect(flow)

        self.clusterer.apply_kmeans(flows)
        self.clusterer.apply_dbscan(flows)

        return AnalysisResult(
            flows=flows,
            protocol_distribution=self.stats.protocol_distribution(flows),
            packet_size_histogram=self.stats.packet_size_histogram(flows),
            flow_durations=self.stats.flow_duration_distribution(flows),
            pps_distribution=self.stats.pps_distribution(flows),
        )
