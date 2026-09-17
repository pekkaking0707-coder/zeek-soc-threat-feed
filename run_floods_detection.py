"""Detection runner — PS class (a) DDoS / floods (PLAN §6, build order #4).

Adapters:
  --pcap datasets/syn_flood.pcap     scapy reader (labeled runs)
  --zeek-log conn.log [--follow]     Zeek TSV (per-flow; SYN flags, UDP, duration, bytes)

Flood detection: per-source rate thresholds + source-IP entropy (spoofed floods);
slowloris via concurrent long-lived low-byte flows.
Alerts -> stdout JSONL, optional --out file and --post-url dashboard push.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone

from detectors.floods import FloodDetector

DET = FloodDetector()


def _emit(alert, out) -> None:
    line = alert.model_dump_json()
    print(line)
    if out:
        out.write(line + "\n")
        out.flush()


def _post(alert, url: str | None) -> None:
    if not url:
        return
    try:
        req = urllib.request.Request(url, data=alert.model_dump_json().encode(),
                                     headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except OSError as e:
        print(f"# dashboard post failed: {e}", file=sys.stderr)


def handle_pkt(ts: float, src: str, dst: str, dst_port: int | None,
               pkt_type: str, out, post_url: str | None,
               cooldown: dict[str, float], extra: dict | None = None) -> None:
    features = {
        "ts": ts,
        "src": src,
        "dst": dst,
        "dst_port": dst_port,
        "pkt_type": pkt_type,
    }
    if extra:
        features.update(extra)

    confidence, evidence = DET.score(features)
    if confidence is None:
        return
    # For flood types, use aggregate cooldown key to avoid per-source spam
    if pkt_type in ("syn", "udp"):
        key = f"agg|{pkt_type}"
    else:
        key = f"{src}|{pkt_type}"
    if ts - cooldown.get(key, 0.0) < 10.0:
        return
    cooldown[key] = ts
    from detectors.floods import ThreatClass
    tc = features.get("_threat_class", ThreatClass.SYN_FLOOD)
    alert = DET.make_alert(
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        flow_id=f"{src}->{dst}#{pkt_type}",
        confidence=confidence,
        evidence=evidence)
    if "udp_pps" in [e.feature for e in evidence]:
        alert.threat_class = "udp_flood"
    elif "slowloris_concurrent" in [e.feature for e in evidence]:
        alert.threat_class = "slowloris"
    _emit(alert, out)
    _post(alert, post_url)


def iter_pcap(path: str):
    from scapy.all import IP, TCP, UDP, rdpcap
    for pkt in rdpcap(path):
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt:
            tcp = pkt[TCP]
            if tcp.flags & 0x02:  # SYN
                yield ts, src, dst, int(tcp.dport), "syn", None
        elif UDP in pkt:
            yield ts, src, dst, int(pkt[UDP].dport), "udp", None


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap")
    src.add_argument("--zeek-log")
    p.add_argument("--follow", action="store_true")
    p.add_argument("--out")
    p.add_argument("--post-url")
    a = p.parse_args()

    out = open(a.out, "a", encoding="utf-8") if a.out else None
    cooldown: dict[str, float] = {}

    if a.pcap:
        for ts, s, d, port, ptype, extra in iter_pcap(a.pcap):
            handle_pkt(ts, s, d, port, ptype, out, a.post_url, cooldown, extra)
    else:
        from ingest import zeek_log
        rows = zeek_log.follow(a.zeek_log) if a.follow else zeek_log.iter_rows(a.zeek_log)
        for row in rows:
            try:
                proto = row.get("proto", "").lower()
                if proto == "tcp" and "S" in row.get("conn_state", ""):
                    handle_pkt(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                               int(row["id.resp_p"]), "syn", out, a.post_url, {}, None)
                elif proto == "udp":
                    handle_pkt(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                               int(row["id.resp_p"]), "udp", out, a.post_url, {}, None)
                # slowloris via conn.log: long duration + low bytes
                dur = float(row.get("duration", 0) or 0)
                orig_bytes = int(row.get("orig_bytes", 0) or 0)
                if proto == "tcp" and dur > 30 and orig_bytes < 1000:
                    handle_pkt(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                               int(row["id.resp_p"]), "slowloris_flow",
                               out, a.post_url, {},
                               {"bytes": orig_bytes, "start_ts": float(row["ts"]) - dur})
            except (KeyError, ValueError):
                continue

    # Note: for Zeek mode, need to write alerts if using a.out
    # (omitted for brevity; add out.close() if needed)


if __name__ == "__main__":
    main()