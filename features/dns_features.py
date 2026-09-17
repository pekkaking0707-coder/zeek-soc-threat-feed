"""Per-client DNS features over a sliding window (PLAN §6 class c).

Aggregates raw query events (ts, qname, qtype) per client and produces the
feature dicts consumed by DGADetector (per-query) and DNSTunnelDetector
(per client-window). Packet tier by nature — QNAMEs only exist here.
"""

from __future__ import annotations

from detectors.dns_family import shannon_entropy
from features.windowing import SlidingWindow

QTYPE_TUNNEL = {"TXT", "NULL", "CNAME", "MX"}


class DNSClientAggregator:
    def __init__(self, window_s: float = 60.0):
        self.window_s = window_s
        self.win = SlidingWindow(window_s)

    def add_query(self, client: str, ts: float, qname: str, qtype: str) -> None:
        self.win.add(client, ts, {"ts": ts, "qname": qname, "qtype": qtype.upper()})

    def per_query_features(self, qname: str) -> dict:
        # Variable labels = all but the registrable-domain suffix (last two).
        # Max entropy across them: tunnelling payloads hide in non-first
        # labels, full-QNAME entropy is diluted by constant suffixes.
        labels = qname.split(".")
        var = labels[:-2] if len(labels) > 2 else labels[:1]
        ents = [shannon_entropy(l) for l in var]
        return {
            "qname": qname,
            "qname_entropy": round(max(ents, default=0.0), 3),
            "longest_label": max((len(l) for l in var), default=0),
            "digit_fraction": round(
                sum(c.isdigit() for c in qname) / max(1, len(qname)), 3),
        }

    def window_features(self, client: str) -> dict:
        events = self.win.snapshot(client)
        if not events:
            return {}
        qnames = [e["qname"] for e in events]
        span_s = max(1.0, events[-1]["ts"] - events[0]["ts"])
        txtish = sum(1 for e in events if e["qtype"] in QTYPE_TUNNEL)
        return {
            "client": client,
            "qps": round(len(events) / span_s, 2),
            "qname_max_len": max(len(q) for q in qnames),
            "txt_ratio": round(txtish / len(events), 3),
            "label_count_max": max(q.count(".") for q in qnames),
            "window_events": len(events),
        }
