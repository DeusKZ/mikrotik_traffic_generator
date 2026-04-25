from __future__ import annotations

from pathlib import Path

from app.core.models import Flow
from app.generators.mikrotik import MikroTikProfileGenerator
from app.generators.moongen import MoonGenProfileGenerator
from app.generators.pktgen import PktgenDpdkProfileGenerator
from app.generators.trex import TRexProfileGenerator


class GeneratorManager:
    def __init__(self) -> None:
        self.generators = {
            "trex": TRexProfileGenerator(),
            "mikrotik": MikroTikProfileGenerator(),
            "moongen": MoonGenProfileGenerator(),
            "pktgen-dpdk": PktgenDpdkProfileGenerator(),
        }

    def generate(self, flows: list[Flow], targets: list[str], output_dir: str) -> list[Path]:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        artifacts: list[Path] = []

        for target in targets:
            generator = self.generators.get(target)
            if generator is None:
                continue
            artifacts.append(generator.generate(flows, out))

        return artifacts
