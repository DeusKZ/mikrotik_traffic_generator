from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pyshark
from scapy.all import PcapReader  # type: ignore
from scapy.layers.inet import ICMP, IP, TCP, UDP  # type: ignore

from app.core.models import Flow, Protocol

FlowKey = tuple[str, str, int, int, Protocol]


class PcapParser:
    """Streaming parser for PCAP files with scapy and pyshark fallback."""

    def __init__(self, pcap_path: str) -> None:
        self.pcap_path = Path(pcap_path)
        if not self.pcap_path.exists():
            raise FileNotFoundError(f"PCAP not found: {pcap_path}")

    def parse_flows(self) -> list[Flow]:
        flows: dict[FlowKey, Flow] = {}
        try:
            for packet in self._iter_scapy_packets():
                self._consume_scapy_packet(packet, flows)
        except Exception:
            for packet in self._iter_pyshark_packets():
                self._consume_pyshark_packet(packet, flows)

        for flow in flows.values():
            if len(flow.timestamps) > 1:
                flow.duration = flow.timestamps[-1] - flow.timestamps[0]
                flow.pps = len(flow.timestamps) / max(flow.duration, 1e-6)
                flow.inter_packet_gaps = [
                    flow.timestamps[i] - flow.timestamps[i - 1]
                    for i in range(1, len(flow.timestamps))
                ]
        return list(flows.values())

    def _iter_scapy_packets(self) -> Iterator:
        with PcapReader(str(self.pcap_path)) as packets:
            for packet in packets:
                if IP in packet:
                    yield packet

    def _iter_pyshark_packets(self) -> Iterator:
        capture = pyshark.FileCapture(str(self.pcap_path), keep_packets=False)
        yield from capture

    def _consume_scapy_packet(self, packet, flows: dict[FlowKey, Flow]) -> None:
        ip = packet[IP]
        proto = Protocol.OTHER
        src_port = 0
        dst_port = 0
        if TCP in packet:
            proto = Protocol.TCP
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
        elif UDP in packet:
            proto = Protocol.UDP
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
        elif ICMP in packet:
            proto = Protocol.ICMP

        key: FlowKey = (ip.src, ip.dst, src_port, dst_port, proto)
        if key not in flows:
            flows[key] = Flow(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
            )

        flow = flows[key]
        flow.packet_sizes.append(len(packet))
        flow.timestamps.append(float(packet.time))

    def _consume_pyshark_packet(self, packet, flows: dict[FlowKey, Flow]) -> None:
        ip = packet.ip

        l4 = None
        if hasattr(packet, "tcp"):
            l4 = packet.tcp
        elif hasattr(packet, "udp"):
            l4 = packet.udp

        src_port = int(l4.srcport) if l4 else 0
        dst_port = int(l4.dstport) if l4 else 0

        if hasattr(packet, "tcp"):
            proto = Protocol.TCP
        elif hasattr(packet, "udp"):
            proto = Protocol.UDP
        elif hasattr(packet, "icmp"):
            proto = Protocol.ICMP
        else:
            proto = Protocol.OTHER

        key: FlowKey = (ip.src, ip.dst, src_port, dst_port, proto)
        if key not in flows:
            flows[key] = Flow(
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=src_port,
                dst_port=dst_port,
                protocol=proto,
            )

        flow = flows[key]
        flow.packet_sizes.append(int(packet.length))
        flow.timestamps.append(float(packet.sniff_timestamp))
