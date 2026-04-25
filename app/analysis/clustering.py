from __future__ import annotations

import numpy as np
from sklearn.cluster import DBSCAN, KMeans

from app.core.models import Flow


class FlowClusterer:
    def build_features(self, flows: list[Flow]) -> np.ndarray:
        features: list[list[float]] = []
        for flow in flows:
            avg_size = float(np.mean(flow.packet_sizes)) if flow.packet_sizes else 0.0
            std_size = float(np.std(flow.packet_sizes)) if flow.packet_sizes else 0.0
            features.append([avg_size, std_size, flow.duration, flow.pps])
        return np.array(features, dtype=float)

    def apply_kmeans(self, flows: list[Flow], n_clusters: int = 3) -> None:
        if len(flows) < n_clusters:
            return
        x = self.build_features(flows)
        labels = KMeans(n_clusters=n_clusters, n_init="auto", random_state=42).fit_predict(x)
        for flow, label in zip(flows, labels, strict=False):
            flow.cluster_label = int(label)

    def apply_dbscan(self, flows: list[Flow], eps: float = 0.5, min_samples: int = 5) -> None:
        if len(flows) < min_samples:
            return
        x = self.build_features(flows)
        labels = DBSCAN(eps=eps, min_samples=min_samples).fit_predict(x)
        for flow, label in zip(flows, labels, strict=False):
            flow.cluster_label = int(label)
