from __future__ import annotations

from pathlib import Path

from app.core.models import Flow
from app.generators.base import ProfileGenerator


class TRexProfileGenerator(ProfileGenerator):
    def generate(self, flows: list[Flow], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        profile_path = output_dir / "trex_profile.py"
        streams = []
        for flow in flows:
            avg_size = (
                int(sum(flow.packet_sizes) / len(flow.packet_sizes)) if flow.packet_sizes else 64
            )
            streams.append(
                {
                    "src": str(flow.src_ip),
                    "dst": str(flow.dst_ip),
                    "sport": flow.src_port,
                    "dport": flow.dst_port,
                    "proto": flow.protocol.value,
                    "pps": max(int(flow.pps), 1),
                    "size": avg_size,
                }
            )

        profile = (
            "# Auto-generated TRex profile\n"
            "from trex.stl.api import *\n\n"
            f"STREAMS = {streams}\n\n"
            "def get_streams(direction=0, **kwargs):\n"
            "    result = []\n"
            "    for s in STREAMS:\n"
            "        pkt = Ether()/IP(src=s['src'], dst=s['dst'])\n"
            "        if s['proto'] == 'tcp':\n"
            "            pkt /= TCP(sport=s['sport'], dport=s['dport'])\n"
            "        elif s['proto'] == 'udp':\n"
            "            pkt /= UDP(sport=s['sport'], dport=s['dport'])\n"
            "        else:\n"
            "            pkt /= Raw(b'x' * max(0, s['size'] - len(pkt)))\n"
            "        result.append(\n"
            "            STLStream(\n"
            "                packet=STLPktBuilder(pkt=pkt),\n"
            "                mode=STLTXCont(pps=s['pps'])\n"
            "            )\n"
            "        )\n"
            "    return result\n"
        )
        profile_path.write_text(profile)
        return profile_path
