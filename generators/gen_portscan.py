"""PS class (e) generator: TCP port scan — fan-out across many dst ports.

One source, N distinct destination ports, fixed spacing (fits inside the
detector's sliding window). Pair with a benign pcap for the FPR check.
"""

from __future__ import annotations

import argparse
import random
import time

from scapy.all import IP, TCP, Ether, wrpcap


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--src", default="10.200.0.66")
    p.add_argument("--dst", default="10.200.0.2")
    p.add_argument("--ports", type=int, default=100)
    p.add_argument("--start-port", type=int, default=1)
    p.add_argument("--spacing-s", type=float, default=0.05)
    p.add_argument("--out", default="datasets/port_scan.pcap")
    a = p.parse_args()

    rng = random.Random()
    pkts = []
    t = time.time()
    for i in range(a.ports):
        t += a.spacing_s
        pkt = Ether() / IP(src=a.src, dst=a.dst) / \
            TCP(sport=rng.randint(40000, 60000), dport=a.start_port + i,
                flags="S", seq=rng.randint(0, 2**32 - 1))
        pkt.time = t
        pkts.append(pkt)
    wrpcap(a.out, pkts)
    print(f"wrote {len(pkts)} SYN probes to ports {a.start_port}..{a.start_port + a.ports - 1} -> {a.out}")


if __name__ == "__main__":
    main()
