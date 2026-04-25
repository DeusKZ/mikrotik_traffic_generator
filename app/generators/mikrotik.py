from __future__ import annotations

from pathlib import Path

from app.core.models import Flow
from app.generators.base import ProfileGenerator


class MikroTikProfileGenerator(ProfileGenerator):
    def generate(self, flows: list[Flow], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        profile_path = output_dir / "mikrotik_profile.rsc"

        lines = ["# Auto-generated RouterOS traffic generator profile"]
        for flow in flows:
            avg_size = (
                int(sum(flow.packet_sizes) / len(flow.packet_sizes)) if flow.packet_sizes else 64
            )
            pps = max(int(flow.pps), 1)
            lines.append(
                "/tool traffic-generator stream add "
                f"packet-size={avg_size} rate={pps}pps "
                f"src-address={flow.src_ip} dst-address={flow.dst_ip} "
                f"protocol={flow.protocol.value} src-port={flow.src_port} dst-port={flow.dst_port}"
            )

        profile_path.write_text("\n".join(lines) + "\n")
        return profile_path
