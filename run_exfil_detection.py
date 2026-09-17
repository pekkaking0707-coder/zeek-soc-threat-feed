"""Detection runner — PS class (f) data exfiltration (build order #5).

Adapters:
  --zeek-log conn.log [--follow]   Zeek TSV (per-flow byte counts)

Exfiltration detection: per-host outbound:inbound byte ratio from flow records;
flag sustained outbound bias inconsistent with baseline.
Alerts -> stdout JSONL, optional --out file and --post-url dashboard push.

Note: PCAP input not yet implemented for exfil; use Zeek conn.log for now.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone

from detectors.exfil import ExfilDetector

DET = ExfilDetector()


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


def handle_flow(ts: float, host: str, orig_bytes: int, resp_bytes: int,
                out, post_url: str | None, cooldown: dict[str, float]) -> None:
    confidence, evidence = DET.observe_flow(host, orig_bytes, resp_bytes)
    if confidence is None:
        return
    if ts - cooldown.get(host, 0.0) < 300.0:  # 5-min cooldown per host
        return
    cooldown[host] = ts
    alert = DET.make_alert(
        timestamp=datetime.fromtimestamp(ts, tz=timezone.utc),
        flow_id=f"{host}#exfil",
        confidence=confidence,
        evidence=evidence)
    _emit(alert, out)
    _post(alert, post_url)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--zeek-log", required=True)
    p.add_argument("--follow", action="store_true")
    p.add_argument("--out")
    p.add_argument("--post-url")
    a = p.parse_args()

    out = open(a.out, "a", encoding="utf-8") if a.out else None
    cooldown: dict[str, float] = {}

    from ingest import zeek_log
    rows = zeek_log.follow(a.zeek_log) if a.follow else zeek_log.iter_rows(a.zeek_log)
    for row in rows:
        try:
            handle_flow(float(row["ts"]), row["id.orig_h"],
                        int(row["orig_bytes"]), int(row["resp_bytes"]),
                        out, a.post_url, cooldown)
        except (KeyError, ValueError):
            continue

    if out:
        out.close()


if __name__ == "__main__":
    main()