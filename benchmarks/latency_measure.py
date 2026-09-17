"""Latency percentiles for constraint (c): packet timestamp -> dashboard receipt.

Usage:  python benchmarks/latency_measure.py alerts.jsonl
Each alert line must carry "packet_ts" (capture time) and "emitted_ts"
(dashboard receipt). Reports p50/p95 in seconds. Extend with pcap correlation
(scapy rdpcap timestamps) once the replay harness is wired.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime


def parse(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def main(path: str) -> None:
    deltas = []
    for line in open(path, encoding="utf-8"):
        rec = json.loads(line)
        if "packet_ts" in rec and "emitted_ts" in rec:
            deltas.append((parse(rec["emitted_ts"]) - parse(rec["packet_ts"])).total_seconds())
    if not deltas:
        print("no paired timestamps found")
        return
    deltas.sort()

    def pct(p: float) -> float:
        i = min(len(deltas) - 1, int(round(p / 100 * (len(deltas) - 1))))
        return deltas[i]

    print(f"n={len(deltas)}  p50={pct(50):.2f}s  p95={pct(95):.2f}s  max={deltas[-1]:.2f}s")
    print("Planning SLA: p95 <= 5s (PLAN §7c) — report measured, never the target.")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "alerts.jsonl")
