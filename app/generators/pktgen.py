from __future__ import annotations

from pathlib import Path

from app.core.models import Flow
from app.generators.base import ProfileGenerator


class PktgenDpdkProfileGenerator(ProfileGenerator):
    def generate(self, flows: list[Flow], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        profile_path = output_dir / "pktgen_config.cfg"

        lines = ["# Auto-generated pktgen-dpdk config"]
        for idx, flow in enumerate(flows, start=0):
            avg_size = (
                int(sum(flow.packet_sizes) / len(flow.packet_sizes)) if flow.packet_sizes else 64
            )
            pps = max(int(flow.pps), 1)
            lines.extend(
                [
                    f"set {idx} src ip {flow.src_ip}",
                    f"set {idx} dst ip {flow.dst_ip}",
                    f"set {idx} proto {flow.protocol.value}",
                    f"set {idx} sport {flow.src_port}",
                    f"set {idx} dport {flow.dst_port}",
                    f"set {idx} size {avg_size}",
                    f"set {idx} rate {pps}",
                    f"enable {idx} range",
                ]
            )

        profile_path.write_text("\n".join(lines) + "\n")
        return profile_path
