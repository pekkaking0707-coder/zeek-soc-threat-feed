"""PS class (b): botnet C2 beaconing — periodicity on IAT series (PLAN §6).

KS-test against the calibrated inter-arrival distribution + CUSUM drift on
per-(src,dst) series; low-variance regular flows toward a small destination
set score high. The same machinery is reused by encrypted_malware (d).
Build order #3.
"""

from __future__ import annotations

from collections import defaultdict, deque

from detectors.base import Detector
from alerts.schema import Evidence, ThreatClass


class BeaconingDetector(Detector):
    name = "beaconing_ks_cusum_v1"
    threat_class = ThreatClass.BEACONING

    def __init__(self, window_n: int = 30, iat_cv_max: float = 0.35,
                 min_samples: int = 6):
        self.window_n = window_n
        self.iat_cv_max = iat_cv_max  # coefficient of variation ceiling = regularity
        self.min_samples = min_samples
        self._series: dict[tuple[str, str], deque[float]] = defaultdict(lambda: deque(maxlen=window_n))

    def observe_iat(self, src: str, dst: str, iat_s: float) -> tuple[float | None, list[Evidence]]:
        dq = self._series[(src, dst)]
        dq.append(iat_s)
        if len(dq) < self.min_samples:
            return None, []
        mean = sum(dq) / len(dq)
        var = sum((x - mean) ** 2 for x in dq) / len(dq)
        cv = (var ** 0.5) / mean if mean > 0 else float("inf")
        if cv > self.iat_cv_max:
            return None, []
        confidence = min(1.0, 0.5 + 0.5 * (self.iat_cv_max - cv) / self.iat_cv_max)
        ev = [
            Evidence(feature="iat_mean_s", value=round(mean, 3)),
            Evidence(feature="iat_cv", value=round(cv, 3), threshold=self.iat_cv_max),
            Evidence(feature="samples", value=len(dq)),
        ]
        return round(confidence, 4), ev

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        # TODO: KS-test vs baseline + CUSUM change-point (scipy.stats.kstest);
        # destination-set concentration across sources. See docs/features.md.
        return self.observe_iat(features["src"], features["dst"], features["iat_s"])
