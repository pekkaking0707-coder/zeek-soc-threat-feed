"""Detection runner — PS class (b) botnet C2 beaconing (PLAN §6, build order #3).

Adapters:
  --pcap datasets/beaconing.pcap    scapy reader (labeled runs)
  --zeek-log conn.log [--follow]    Zeek TSV (per-flow inter-arrival timestamps)

Beaconing detection: per-(src,dst) inter-arrival-time series, low-CV flag.
KS-test against baseline + CUSUM drift detection. Alerts -> stdout JSONL,
optional --out file and --post-url dashboard push.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone

from detectors.beaconing import BeaconingDetector

DET = BeaconingDetector()


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


def handle_iat(ts: float, src: str, dst: str, out, post_url: str | None,
               cooldown: dict[str, float]) -> None:
    confidence, evidence = DET.observe_iat(src, dst, ts)
    if confidence is None:
        return
    key = f"{src}|{dst}"
    if ts - cooldown.get(key, 0.0) < 30.0:
        return
    cooldown[key] = ts
    alert = DET.make_alert(
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        flow_id=f"{src}->{dst}#beacon",
        confidence=confidence,
        evidence=evidence)
    _emit(alert, out)
    _post(alert, post_url)


def iter_pcap_tcp(path: str):
    from scapy.all import IP, TCP, rdpcap
    for pkt in rdpcap(path):
        if TCP in pkt and IP in pkt:
            yield float(pkt.time), pkt[IP].src, pkt[IP].dst


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
        for ts, s, d in iter_pcap_tcp(a.pcap):
            handle_iat(ts, s, d, out, a.post_url, cooldown)
    else:
        from ingest import zeek_log
        rows = zeek_log.follow(a.zeek_log) if a.follow else zeek_log.iter_rows(a.zeek_log)
        for row in rows:
            try:
                handle_iat(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                           out, a.post_url, cooldown)
            except (KeyError, ValueError):
                continue

    if out:
        out.close()


if __name__ == "__main__":
    main()