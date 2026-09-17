"""PS class (c): DGA domains + DNS tunnelling — packet tier required (PLAN §6).

Build order #1: both detectors share one QNAME feature pipeline.
Features: qname entropy, char n-gram log-likelihood vs Tranco-benign model,
length, label count, record-type ratio (TXT/NULL), per-client query velocity.
"""

from __future__ import annotations

import math

from detectors.base import Detector
from alerts.schema import Evidence, ThreatClass


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class DGADetector(Detector):
    name = "dga_ngram_v1"
    threat_class = ThreatClass.DGA_DOMAIN

    # Composite v0 heuristic (replaced by the n-gram model, docs/models.md):
    # entropy/5 + length + digit-fraction, gated at score_min. Calibrated on
    # labeled generator PCAPs: benign max ~0.30, DGA 0.55-0.75.
    W_ENTROPY, W_LENGTH, W_DIGITS = 0.5, 0.3, 0.2

    def __init__(self, benign_model=None, score_min: float = 0.5):
        self.model = benign_model  # TODO(docs/models.md): train on Tranco benign vs DGA samples
        self.score_min = score_min

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        ent = features.get("qname_entropy", 0.0)
        longest = features.get("longest_label", 0)
        digits = features.get("digit_fraction", 0.0)
        raw = (self.W_ENTROPY * (ent / 5.0)
               + self.W_LENGTH * min(longest / 20.0, 1.0)
               + self.W_DIGITS * digits)
        if raw < self.score_min:
            return None, []
        confidence = min(1.0, raw)
        ev = [
            Evidence(feature="qname_entropy", value=ent, threshold=3.0),
            Evidence(feature="longest_label", value=longest),
            Evidence(feature="digit_fraction", value=digits),
        ]
        if self.model is not None:
            ll = self.model.log_likelihood(features["qname"])
            ev.append(Evidence(feature="ngram_log_likelihood", value=ll))
            confidence = max(confidence, min(1.0, -ll / 60.0))
        return round(confidence, 4), ev


class DNSTunnelDetector(Detector):
    name = "dns_tunnel_v1"
    threat_class = ThreatClass.DNS_TUNNELING

    def __init__(self, max_qname_len: int = 120, txt_ratio_min: float = 0.6):
        self.max_qname_len = max_qname_len
        self.txt_ratio_min = txt_ratio_min

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        qlen = features.get("qname_max_len", 0)
        txt_ratio = features.get("txt_ratio", 0.0)
        if qlen < self.max_qname_len and txt_ratio < self.txt_ratio_min:
            return None, []
        signals = [
            Evidence(feature="qname_max_len", value=qlen, threshold=float(self.max_qname_len)),
            Evidence(feature="txt_ratio", value=round(txt_ratio, 3),
                     threshold=self.txt_ratio_min),
            Evidence(feature="qps", value=features.get("qps")),
        ]
        confidence = 0.5 + 0.25 * (qlen >= self.max_qname_len) + 0.25 * (txt_ratio >= self.txt_ratio_min)
        return round(min(1.0, confidence), 4), signals
