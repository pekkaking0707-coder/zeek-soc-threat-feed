"""Detector interface — every detector returns (confidence | None, evidence).

confidence None means "no alert". Confidence is a deterministic function of
the features (PLAN §5): normalized deviation beyond threshold for statistical
detectors, model probability for trained ones (e.g., DGA n-gram scorer).
Severity is never set here directly — Alert computes it from the class base
and confidence.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from alerts.schema import Alert, Evidence, ThreatClass


class Detector(ABC):
    name: str = "detector_v0"
    threat_class: ThreatClass

    @abstractmethod
    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        """Return (confidence, evidence) or (None, []) when nothing fires."""

    def make_alert(self, timestamp, flow_id: str,
                   confidence: float, evidence: list[Evidence]) -> Alert:
        return Alert(
            timestamp=timestamp,
            flow_id=flow_id,
            threat_class=self.threat_class,
            confidence_score=confidence,
            supporting_evidence=evidence,
        )
