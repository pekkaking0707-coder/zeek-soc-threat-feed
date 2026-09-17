"""PS class (f): data exfiltration — asymmetric byte ratios from flow records.

Requires both directions mirrored in (PLAN §3 direction-dependency note).
Per-host outbound:inbound byte ratio vs calibrated baseline. Build order #5.
"""

from __future__ import annotations

from collections import defaultdict

from detectors.base import Detector
from alerts.schema import Evidence, ThreatClass


class ExfilDetector(Detector):
    name = "exfil_byte_ratio_v1"
    threat_class = ThreatClass.DATA_EXFILTRATION

    def __init__(self, ratio_threshold: float = 10.0, min_outbound_bytes: int = 50_000):
        self.ratio_t = ratio_threshold
        self.min_out = min_outbound_bytes
        self._bytes: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # host -> [out, in]

    def observe_flow(self, internal_host: str, orig_bytes: int, resp_bytes: int) -> tuple[float | None, list[Evidence]]:
        b = self._bytes[internal_host]
        b[0] += orig_bytes
        b[1] += resp_bytes
        out_b, in_b = b
        if out_b < self.min_out:
            return None, []
        ratio = out_b / max(in_b, 1)
        if ratio < self.ratio_t:
            return None, []
        confidence = min(1.0, 0.5 + 0.5 * (ratio / self.ratio_t - 1.0))
        ev = [
            Evidence(feature="out_in_ratio", value=round(ratio, 2), threshold=self.ratio_t),
            Evidence(feature="outbound_bytes", value=out_b),
            Evidence(feature="inbound_bytes", value=in_b),
        ]
        return round(confidence, 4), ev

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        return self.observe_flow(features["host"], features["orig_bytes"], features["resp_bytes"])
