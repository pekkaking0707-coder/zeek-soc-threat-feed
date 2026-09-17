"""PS class (e): reconnaissance / port scanning — fan-out counter (PLAN §6).

Sliding window of distinct (dst_ip, dst_port) pairs per source; flag when the
count crosses the fan-out threshold. Build order #2 (trivial).
"""

from __future__ import annotations

from collections import defaultdict, deque

from detectors.base import Detector
from alerts.schema import Evidence, ThreatClass


class PortScanDetector(Detector):
    name = "port_scan_fanout_v1"
    threat_class = ThreatClass.PORT_SCAN

    def __init__(self, window_s: float = 10.0, fanout_threshold: int = 50):
        self.window_s = window_s
        self.threshold = fanout_threshold
        self._seen: dict[str, deque[tuple[float, str]]] = defaultdict(deque)

    def observe(self, src: str, dst_ip: str, dst_port: int, ts: float) -> tuple[float | None, list[Evidence]]:
        dq = self._seen[src]
        dq.append((ts, f"{dst_ip}:{dst_port}"))
        cutoff = ts - self.window_s
        while dq and dq[0][0] < cutoff:
            dq.popleft()
        distinct = len({target for _, target in dq})
        if distinct < self.threshold:
            return None, []
        ratio = distinct / self.threshold
        confidence = min(1.0, 0.5 + 0.5 * (ratio - 1.0))
        ev = [Evidence(feature="fanout_distinct_targets", value=distinct,
                       threshold=float(self.threshold))]
        return round(confidence, 4), ev

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        return self.observe(features["src"], features["dst_ip"],
                            features["dst_port"], features["ts"])
