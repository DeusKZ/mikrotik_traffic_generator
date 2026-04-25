from __future__ import annotations

import numpy as np

from app.core.models import Flow, TrafficPattern


class TrafficPatternDetector:
    def detect(self, flow: Flow) -> TrafficPattern:
        if len(flow.inter_packet_gaps) < 3:
            return TrafficPattern.UNKNOWN

        gaps = np.array(flow.inter_packet_gaps)
        mean = gaps.mean()
        std = gaps.std()

        if std / max(mean, 1e-9) < 0.05:
            return TrafficPattern.CONSTANT

        peaks = np.where(gaps > mean + (2 * std))[0]
        if len(peaks) > max(1, len(gaps) * 0.1):
            return TrafficPattern.BURST

        fft = np.fft.rfft(gaps - mean)
        if len(fft) > 2 and np.max(np.abs(fft[1:])) > np.abs(fft[0]) * 0.2:
            return TrafficPattern.PERIODIC

        return TrafficPattern.UNKNOWN
