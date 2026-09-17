"""Detection runner — PS class (c) end-to-end (PLAN §6, build order #1).

Two input adapters, one detection path:
  --pcap datasets/x.pcap        scapy reader (labeled unit/eval runs)
  --zeek-log dns.log [--follow] Zeek TSV (live capture in the VM)

Alerts stream to stdout as JSONL and optionally POST to the dashboard
(--post-url http://host:8080/alerts). Streaming by construction: each event
is processed incrementally; window features evaluated as data arrives.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone

from alerts.schema import Alert, ThreatClass
from detectors.dns_family import DGADetector, DNSTunnelDetector
from features.dns_features import DNSClientAggregator

DGA = DGADetector()
TUNNEL = DNSTunnelDetector()


def _flow_id(client: str, resolver: str) -> str:
    return f"{client}-> {resolver}#dns".replace("> ", ">")


def _emit(alert: Alert, out) -> None:
    line = alert.model_dump_json()
    print(line)
    if out:
        out.write(line + "\n")
        out.flush()


def _post(alert: Alert, url: str | None) -> None:
    if not url:
        return
    try:
        req = urllib.request.Request(
            url, data=alert.model_dump_json().encode(),
            headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=5)
    except OSError as e:
        print(f"# dashboard post failed: {e}", file=sys.stderr)


def handle_query(ts: float, client: str, resolver: str, qname: str, qtype: str,
                 agg: DNSClientAggregator, out, post_url: str | None,
                 cooldown: dict[str, float], last_tunnel: dict[str, float]) -> None:
    qname = qname.rstrip(".")
    agg.add_query(client, ts, qname, qtype)

    def fire(detector, confidence, evidence):
        key = f"{client}|{detector.name}"
        if ts - cooldown.get(key, 0.0) < 10.0:
            return
        cooldown[key] = ts
        alert = detector.make_alert(
            timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
            flow_id=_flow_id(client, resolver),
            confidence=confidence,
            evidence=evidence)
        _emit(alert, out)
        _post(alert, post_url)

    wf = agg.window_features(client)
    conf, ev = TUNNEL.score(wf)
    if conf is not None:
        last_tunnel[client] = ts
        fire(TUNNEL, conf, ev)
        return

    # Tunnel-priority suppression: base32 payload labels trip the DGA entropy
    # heuristic; when the window already diagnosed tunnelling for this client,
    # the more specific classification wins (class-purity for evaluation).
    if ts - last_tunnel.get(client, -1e9) < 30.0:
        return
    conf, ev = DGA.score(agg.per_query_features(qname))
    if conf is not None:
        fire(DGA, conf, ev)


def iter_pcap_dns(path: str):
    from scapy.all import DNS, DNSQR, IP, rdpcap
    for pkt in rdpcap(path):
        if DNS not in pkt or IP not in pkt or pkt[DNS].qd is None:
            continue
        try:
            qname = pkt[DNSQR].qname.decode(errors="replace")
        except Exception:
            continue
        yield float(pkt.time), pkt[IP].src, pkt[IP].dst, qname, \
            (pkt[DNS].qd.qtype if hasattr(pkt[DNS].qd, "qtype") else "A")


QTYPE_NAMES = {1: "A", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV",
               255: "ANY", 252: "AXFR", 10: "NULL"}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--pcap")
    src.add_argument("--zeek-log")
    p.add_argument("--follow", action="store_true", help="tail -F the zeek log (live)")
    p.add_argument("--window-s", type=float, default=60.0)
    p.add_argument("--out", help="append JSONL alerts to this file")
    p.add_argument("--post-url", help="dashboard endpoint, e.g. http://localhost:8080/alerts")
    a = p.parse_args()

    out = open(a.out, "a", encoding="utf-8") if a.out else None
    agg = DNSClientAggregator(window_s=a.window_s)
    cooldown: dict[str, float] = {}
    last_tunnel: dict[str, float] = {}

    if a.pcap:
        for ts, src_ip, dst_ip, qname, qtype in iter_pcap_dns(a.pcap):
            handle_query(ts, src_ip, dst_ip, qname, QTYPE_NAMES.get(int(qtype), "A"),
                         agg, out, a.post_url, cooldown, last_tunnel)
    else:
        from ingest import zeek_log
        rows = zeek_log.follow(a.zeek_log) if a.follow else zeek_log.iter_rows(a.zeek_log)
        for row in rows:
            try:
                handle_query(float(row["ts"]), row["id.orig_h"], row["id.resp_h"],
                             row["query"], row.get("qtype_name", "A"),
                             agg, out, a.post_url, cooldown, last_tunnel)
            except KeyError:
                continue

    if out:
        out.close()


if __name__ == "__main__":
    main()
