"""Detection runner — PS class (e) port scanning (PLAN §6, build order #2).

Adapters:
  --pcap datasets/port_scan.pcap     scapy reader (labeled runs)
  --zeek-log conn.log [--follow]     Zeek TSV (one row per flow observation)

Fan-out: distinct (dst_ip, dst_port) pairs per source in a sliding window;
threshold default 50 (detectors/port_scan.py). Alerts -> stdout JSONL,
optional --out file and --post-url dashboard push.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone

from detectors.port_scan import PortScanDetector

DET = PortScanDetector()


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


def handle_flow(ts: float, src: str, dst_ip: str, dst_port: int,
                out, post_url: str | None, cooldown: dict[str, float]) -> None:
    confidence, evidence = DET.observe(src, dst_ip, dst_port, ts)
    if confidence is None:
        return
    if ts - cooldown.get(src, 0.0) < 10.0:
        return
    cooldown[src] = ts
    alert = DET.make_alert(
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        flow_id=f"{src}->{dst_ip}#scan",
        confidence=confidence,
        evidence=evidence)
    _emit(alert, out)
    _post(alert, post_url)


def iter_pcap_tcp(path: str):
    from scapy.all import IP, TCP, rdpcap
    for pkt in rdpcap(path):
        if TCP not in pkt or IP not in pkt:
            continue
        yield float(pkt.time), pkt[IP].src, pkt[IP].dst, int(pkt[TCP].dport)


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
        for ts, s, d, port in iter_pcap_tcp(a.pcap):
            handle_flow(ts, s, d, port, out, a.post_url, cooldown)
    else:
        from ingest import zeek_log
        rows = zeek_log.follow(a.zeek_log) if a.follow else zeek_log.iter_rows(a.zeek_log)
        for row in rows:
            try:
                handle_flow(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                            int(row["id.resp_p"]), out, a.post_url, cooldown)
            except (KeyError, ValueError):
                continue

    if out:
        out.close()


if __name__ == "__main__":
    main()
