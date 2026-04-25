from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, IPvAnyAddress


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    OTHER = "other"


class TrafficPattern(str, Enum):
    BURST = "burst"
    CONSTANT = "constant"
    PERIODIC = "periodic"
    UNKNOWN = "unknown"


class Flow(BaseModel):
    src_ip: IPvAnyAddress
    dst_ip: IPvAnyAddress
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: Protocol
    packet_sizes: list[int] = Field(default_factory=list)
    timestamps: list[float] = Field(default_factory=list)
    duration: float = 0.0
    pps: float = 0.0
    inter_packet_gaps: list[float] = Field(default_factory=list)
    pattern: TrafficPattern = TrafficPattern.UNKNOWN
    cluster_label: int | Literal[-1] = -1


class RouterConfig(BaseModel):
    host: str
    port: int = 22
    username: str
    password: str


class AnalysisResult(BaseModel):
    flows: list[Flow]
    protocol_distribution: dict[str, int]
    packet_size_histogram: dict[str, list[float]]
    flow_durations: list[float]
    pps_distribution: list[float]
