"""PS class (c) generator part 1: DGA domain queries mixed with benign QNAMEs.

Entropy is controllable via --charset and --label-len; benign names come from
a small built-in sample (swap for the Tranco list in docs/validation.md runs).
"""

from __future__ import annotations

import argparse
import random
import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap

BENIGN = [
    "www.google.com", "api.github.com", "cdn.jsdelivr.net", "mail.protection.outlook.com",
    "www.microsoft.com", "updates.cdn-apple.com", "dns.google", "www.cloudflare.com",
    "packages.python.org", "img.youtube.com",
]


def dga_label(rng: random.Random, charset: str, length: int) -> str:
    return "".join(rng.choice(charset) for _ in range(length))


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--src", default="10.200.0.50")
    p.add_argument("--resolver", default="10.200.0.1")
    p.add_argument("--count", type=int, default=100)
    p.add_argument("--dga-ratio", type=float, default=0.5)
    p.add_argument("--tlds", nargs="+", default=["xyz", "top", "club"])
    p.add_argument("--label-len", type=int, default=16)
    p.add_argument("--out", default="datasets/dga_queries.pcap")
    a = p.parse_args()

    rng = random.Random()
    charset = "abcdefghijklmnopqrstuvwxyz0123456789"
    pkts = []
    t = time.time()
    for _ in range(a.count):
        t += rng.uniform(0.2, 3.0)
        if rng.random() < a.dga_ratio:
            qname = f"{dga_label(rng, charset, a.label_len)}.{rng.choice(a.tlds)}"
        else:
            qname = rng.choice(BENIGN)
        pkt = Ether() / IP(src=a.src, dst=a.resolver) / \
            UDP(sport=rng.randint(30000, 60000), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=qname, qtype="A"))
        pkt.time = t
        pkts.append(pkt)
    wrpcap(a.out, pkts)
    print(f"wrote {len(pkts)} queries ({int(a.dga_ratio * 100)}% DGA) -> {a.out}")


if __name__ == "__main__":
    main()
