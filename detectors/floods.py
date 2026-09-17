"""PS class (a): volumetric/protocol DDoS — SYN floods, UDP reflection/amplification,
spoofed-source floods, slowloris (PLAN §6).

Flow-level rate thresholds + source-IP Shannon entropy (catches spoofed-source
floods with randomized source IPs); slowloris via long-lived near-zero-byte
concurrency. Build order #4.
"""

from __future__ import annotations

import math
from collections import defaultdict, deque

from detectors.base import Detector
from alerts.schema import Evidence, ThreatClass


def source_ip_entropy(ips: list[str]) -> float:
    if not ips:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ip in ips:
        freq[ip] += 1
    n = len(ips)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


class FloodDetector(Detector):
    name = "flood_rate_entropy_v1"
    threat_class = ThreatClass.SYN_FLOOD  # base class; overridden per sub-type

    def __init__(
        self,
        syn_pps_threshold: float = 500.0,
        udp_pps_threshold: float = 800.0,
        slowloris_concurrent_threshold: int = 200,
        slowloris_max_bytes_per_flow: int = 1000,
        slowloris_min_duration_s: float = 30.0,
        entropy_threshold: float = 4.0,
        window_s: float = 1.0,
    ):
        self.syn_t = syn_pps_threshold
        self.udp_t = udp_pps_threshold
        self.slowloris_concurrent_t = slowloris_concurrent_threshold
        self.slowloris_max_bytes = slowloris_max_bytes_per_flow
        self.slowloris_min_dur = slowloris_min_duration_s
        self.entropy_t = entropy_threshold
        self.window_s = window_s

        # per-source tracking
        self._syn_srcs: dict[str, deque[float]] = defaultdict(deque)
        self._udp_srcs: dict[str, deque[float]] = defaultdict(deque)
        self._udp_src_ips: dict[str, set[str]] = defaultdict(set)
        # aggregate tracking for spoofed floods
        self._syn_all: deque[float] = deque()
        self._syn_src_ips: set[str] = set()
        self._udp_all: deque[float] = deque()
        self._udp_src_ips_agg: set[str] = set()
        # slowloris: track concurrent low-byte long-duration flows per src->dst
        self._slowloris: dict[str, dict[tuple[str, int], float]] = defaultdict(dict)

    def _add_syn(self, src: str, ts: float) -> None:
        dq = self._syn_srcs[src]
        dq.append(ts)
        while dq and dq[0] < ts - self.window_s:
            dq.popleft()
        # aggregate tracking
        self._syn_all.append(ts)
        self._syn_src_ips.add(src)
        while self._syn_all and self._syn_all[0] < ts - self.window_s:
            self._syn_all.popleft()

    def _add_udp(self, src: str, dst: str, ts: float) -> None:
        dq = self._udp_srcs[src]
        dq.append(ts)
        while dq and dq[0] < ts - self.window_s:
            dq.popleft()
        self._udp_src_ips[src].add(dst)
        # aggregate tracking for spoofed UDP floods
        self._udp_all.append(ts)
        self._udp_src_ips_agg.add(src)
        while self._udp_all and self._udp_all[0] < ts - self.window_s:
            self._udp_all.popleft()

    def _check_syn_flood(self, src: str, ts: float, window_s: float | None = None) -> tuple[ThreatClass | None, float, list[Evidence]]:
        w = window_s or self.window_s
        cutoff = ts - w
        
        # per-source check
        dq = self._syn_srcs[src]
        while dq and dq[0] < cutoff:
            dq.popleft()
        pps = len(dq) / w
        per_src_fire = pps >= self.syn_t
        
        # aggregate check for spoofed floods
        agg_pps = len(self._syn_all) / w
        agg_fire = agg_pps >= self.syn_t
        
        if not per_src_fire and not agg_fire:
            return None, 0.0, []
        
        # entropy for spoofed detection
        entropy = source_ip_entropy(list(self._syn_src_ips))
        
        if agg_fire and entropy >= self.entropy_t:
            confidence = min(1.0, 0.5 + 0.5 * (agg_pps / self.syn_t - 1.0) + 0.3 * (entropy / self.entropy_t))
            ev = [
                Evidence(feature="syn_pps", value=round(agg_pps, 1), threshold=self.syn_t),
                Evidence(feature="src_ip_entropy", value=round(entropy, 3), threshold=self.entropy_t),
            ]
            return ThreatClass.SYN_FLOOD, round(confidence, 4), ev
        elif per_src_fire:
            confidence = min(1.0, 0.5 + 0.5 * (pps / self.syn_t - 1.0))
            ev = [Evidence(feature="syn_pps", value=round(pps, 1), threshold=self.syn_t)]
            return ThreatClass.SYN_FLOOD, round(confidence, 4), ev
        
        return None, 0.0, []

    def _check_udp_flood(self, src: str, ts: float, window_s: float | None = None) -> tuple[ThreatClass | None, float, list[Evidence]]:
        w = window_s or self.window_s
        cutoff = ts - w
        
        # per-source check
        dq = self._udp_srcs[src]
        while dq and dq[0] < cutoff:
            dq.popleft()
        pps = len(dq) / w
        per_src_fire = pps >= self.udp_t
        
        # aggregate check for spoofed floods
        agg_pps = len(self._udp_all) / w
        agg_fire = agg_pps >= self.udp_t
        
        if not per_src_fire and not agg_fire:
            return None, 0.0, []
        
        # entropy for spoofed detection
        entropy = source_ip_entropy(list(self._udp_src_ips_agg))
        
        if agg_fire and entropy >= self.entropy_t:
            confidence = min(1.0, 0.5 + 0.5 * (agg_pps / self.udp_t - 1.0) + 0.3 * (entropy / self.entropy_t))
            ev = [
                Evidence(feature="udp_pps", value=round(agg_pps, 1), threshold=self.udp_t),
                Evidence(feature="src_ip_entropy", value=round(entropy, 3), threshold=self.entropy_t),
            ]
            return ThreatClass.UDP_FLOOD, round(confidence, 4), ev
        elif per_src_fire:
            entropy = source_ip_entropy(list(self._udp_src_ips[src]))
            confidence = min(1.0, 0.5 + 0.5 * (pps / self.udp_t - 1.0))
            ev = [
                Evidence(feature="udp_pps", value=round(pps, 1), threshold=self.udp_t),
                Evidence(feature="src_ip_entropy", value=round(entropy, 3), threshold=self.entropy_t),
            ]
            return ThreatClass.UDP_FLOOD, round(confidence, 4), ev
        
        return None, 0.0, []

    def _check_slowloris(self, src: str, dst: str, dst_port: int, bytes_count: int, ts: float, start_ts: float) -> tuple[ThreatClass | None, float, list[Evidence]]:
        key = (dst, dst_port)
        if bytes_count <= self.slowloris_max_bytes:
            self._slowloris[src][key] = ts  # update last seen
        else:
            self._slowloris[src].pop(key, None)  # too much data -> not slowloris
            return None, 0.0, []

        dur = ts - start_ts
        if dur < self.slowloris_min_dur:
            return None, 0.0, []

        concurrent = len(self._slowloris[src])
        if concurrent < self.slowloris_concurrent_t:
            return None, 0.0, []

        confidence = min(1.0, 0.5 + 0.5 * (concurrent / self.slowloris_concurrent_t - 1.0))
        ev = [
            Evidence(feature="slowloris_concurrent", value=concurrent, threshold=self.slowloris_concurrent_t),
            Evidence(feature="flow_duration_s", value=round(dur, 1)),
        ]
        return ThreatClass.SLOWLORIS, round(confidence, 4), ev

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        """Dispatch based on feature keys present."""
        ts = features.get("ts")
        if ts is None:
            return None, []

        src = features.get("src")
        dst = features.get("dst")
        dst_port = features.get("dst_port")
        pkt_type = features.get("pkt_type")  # "syn", "udp", "slowloris_flow"

        if src is None or dst is None or ts is None:
            return None, []

        if pkt_type == "syn":
            self._add_syn(src, ts)
            tc, conf, ev = self._check_syn_flood(src, ts)
            if tc:
                return conf, ev
        elif pkt_type == "udp":
            self._add_udp(src, dst, ts)
            tc, conf, ev = self._check_udp_flood(src, ts)
            if tc:
                return conf, ev
        elif pkt_type == "slowloris_flow":
            bytes_count = features.get("bytes", 0)
            start_ts = features.get("start_ts", ts)
            if dst_port is not None:
                tc, conf, ev = self._check_slowloris(src, dst, dst_port, bytes_count, ts, start_ts)
                if tc:
                    return conf, ev

        return None, []


class SlowlorisDetector(Detector):
    """Dedicated slowloris detector for HTTP-layer semantics (optional, PLAN bonus)."""
    name = "slowloris_http_v1"
    threat_class = ThreatClass.SLOWLORIS

    def __init__(self, concurrent_threshold: int = 200, max_req_size: int = 500):
        self.concurrent_t = concurrent_threshold
        self.max_req_size = max_req_size
        self._partial: dict[str, dict[tuple[str, int], float]] = defaultdict(dict)

    def score(self, features: dict) -> tuple[float | None, list[Evidence]]:
        # Expects: src, dst, dst_port, http_req_size, http_headers_complete (bool), ts
        if features.get("pkt_type") != "http_request":
            return None, []
        src = features.get("src")
        dst = features.get("dst")
        dst_port = features.get("dst_port")
        req_size = features.get("http_req_size", 0)
        complete = features.get("http_headers_complete", False)
        ts = features.get("ts", 0)
        if src is None or dst is None or dst_port is None or ts == 0:
            return None, []
        key = (dst, dst_port)
        if req_size > 0 and req_size <= self.max_req_size and not complete:
            self._partial[src][key] = ts
        else:
            self._partial[src].pop(key, None)
            return None, []

        concurrent = len(self._partial[src])
        if concurrent < self.concurrent_t:
            return None, []
        confidence = min(1.0, 0.5 + 0.5 * (concurrent / self.concurrent_t - 1.0))
        ev = [Evidence(feature="slowloris_http_concurrent", value=concurrent, threshold=self.concurrent_t)]
        return round(confidence, 4), ev