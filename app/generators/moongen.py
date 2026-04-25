from __future__ import annotations

from pathlib import Path

from app.core.models import Flow
from app.generators.base import ProfileGenerator


class MoonGenProfileGenerator(ProfileGenerator):
    def generate(self, flows: list[Flow], output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)
        profile_path = output_dir / "moongen_profile.lua"

        lines = ["-- Auto-generated MoonGen profile", 'local mg = require "moongen"']
        lines.append("function master()")
        for idx, flow in enumerate(flows, start=1):
            pps = max(int(flow.pps), 1)
            start_task_line = (
                f"  mg.startTask('flowTask{idx}', '{flow.src_ip}', '{flow.dst_ip}', "
                f"{flow.src_port}, {flow.dst_port}, '{flow.protocol.value}', {pps})"
            )
            lines.append(start_task_line)
        lines.append("  mg.waitForTasks()")
        lines.append("end")
        lines.append("")

        for idx, flow in enumerate(flows, start=1):
            avg_size = (
                int(sum(flow.packet_sizes) / len(flow.packet_sizes)) if flow.packet_sizes else 64
            )
            flow_task_def = (
                f"function flowTask{idx}(src, dst, sport, dport, proto, rate) "
                f"-- size={avg_size} duration={flow.duration:.4f}"
            )
            lines.append(flow_task_def)
            lines.append("  while mg.running() do")
            lines.append("    mg.sleepMillis(10)")
            lines.append("  end")
            lines.append("end")
            lines.append("")

        profile_path.write_text("\n".join(lines))
        return profile_path
