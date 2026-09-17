"""PS class (a) generator: SYN/UDP floods with controllable source-IP entropy.

--spoofed randomizes source IPs (high entropy) so the flood detector's
source-IP entropy branch has something honest to catch.
"""

from __future__ import annotations

import argparse
import random
import time

from scapy.all import IP, UDP, Ether, RandShort, TCP, wrpcap


def rand_ip(rng: random.Random) -> str:
    return f"{rng.randint(1, 223)}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--type", choices=["syn", "udp"], default="syn")
    p.add_argument("--dst", default="10.200.0.2")
    p.add_argument("--dport", type=int, default=80)
    p.add_argument("--packets", type=int, default=5000)
    p.add_argument("--spoofed", action="store_true")
    p.add_argument("--src", default="10.200.0.66")
    p.add_argument("--out", default="datasets/syn_flood.pcap")
    a = p.parse_args()

    rng = random.Random()
    pkts = []
    t = time.time()
    for _ in range(a.packets):
        t += rng.uniform(0.0001, 0.001)
        src = rand_ip(rng) if a.spoofed else a.src
        if a.type == "syn":
            pkt_body = IP(src=src, dst=a.dst) / TCP(sport=RandShort(), dport=a.dport,
                                                    flags="S", seq=RandShort())
        else:
            pkt_body = IP(src=src, dst=a.dst) / UDP(sport=RandShort(), dport=a.dport) / (b"x" * 64)
        pkt = Ether() / pkt_body
        pkt.time = t
        pkts.append(pkt)
    wrpcap(a.out, pkts)
    print(f"wrote {len(pkts)} {a.type} packets ({'spoofed' if a.spoofed else 'fixed'} src) -> {a.out}")


if __name__ == "__main__":
    main()
