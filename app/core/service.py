from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from app.analysis.engine import AnalysisEngine
from app.core.models import AnalysisResult
from app.generators.manager import GeneratorManager
from app.pcap.parser import PcapParser


def _parse_pcap_worker(path: str):
    return PcapParser(path).parse_flows()


class TrafficStudioService:
    def __init__(self) -> None:
        self.analysis_engine = AnalysisEngine()
        self.generator_manager = GeneratorManager()
        self.latest_result: AnalysisResult | None = None

    def analyze_pcap(self, pcap_path: str) -> AnalysisResult:
        with ProcessPoolExecutor(max_workers=1) as pool:
            flows = pool.submit(_parse_pcap_worker, pcap_path).result()
        self.latest_result = self.analysis_engine.analyze(flows)
        return self.latest_result

    def generate_profiles(self, output_dir: str, targets: list[str]) -> list[Path]:
        if not self.latest_result:
            raise ValueError("Analyze PCAP before generating profiles")

        return self.generator_manager.generate(self.latest_result.flows, targets, output_dir)
