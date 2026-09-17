"""PS class (b) generator: C2 beaconing — jittered periodic flows to one dst.

Inter-arrival regularity controlled by --jitter-pct (coefficient of variation
the beaconing detector should catch below its cv threshold).
"""

from __future__ import annotations

import argparse
import random
import time

from scapy.all import IP, TCP, Ether, wrpcap


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--src", default="10.200.0.66")
    p.add_argument("--dst", default="10.200.0.99")
    p.add_argument("--period-s", type=float, default=30.0)
    p.add_argument("--jitter-pct", type=float, default=5.0)
    p.add_argument("--beacons", type=int, default=40)
    p.add_argument("--out", default="datasets/beaconing.pcap")
    a = p.parse_args()

    pkts = []
    t = time.time()
    sport = random.randint(40000, 50000)
    for _ in range(a.beacons):
        t += a.period_s * (1 + random.uniform(-a.jitter_pct, a.jitter_pct) / 100.0)
        pkt = (Ether() / IP(src=a.src, dst=a.dst) /
               TCP(sport=sport, dport=443, flags="PA", seq=1) / (b"\x00" * 32))
        pkt.time = t
        pkts.append(pkt)
    wrpcap(a.out, pkts)
    print(f"wrote {len(pkts)} beacons (period={a.period_s}s +/-{a.jitter_pct}%) -> {a.out}")


if __name__ == "__main__":
    main()
