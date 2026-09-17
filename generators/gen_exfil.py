"""PS class (f) generator: data exfiltration — large outbound transfer.

Creates a pcap with one host sending significantly more data outbound
than inbound, simulating data exfiltration.
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
    p.add_argument("--dport", type=int, default=443)
    p.add_argument("--out-bytes", type=int, default=5_000_000)  # 5 MB outbound
    p.add_argument("--in-bytes", type=int, default=50_000)      # 50 KB inbound
    p.add_argument("--out", default="datasets/exfil.pcap")
    a = p.parse_args()

    rng = random.Random()
    pkts = []
    t = time.time()

    # Simulate a TCP connection: SYN, SYN-ACK, ACK
    sport = rng.randint(40000, 50000)
    t0 = time.time()
    # SYN
    pkt = Ether() / IP(src=a.src, dst=a.dst) / TCP(sport=sport, dport=a.dport, flags="S", seq=1000)
    pkt.time = t0
    pkts.append(pkt)
    # SYN-ACK
    t0 += 0.002
    pkt = Ether() / IP(src=a.dst, dst=a.src) / TCP(sport=a.dport, dport=sport, flags="SA", seq=2000, ack=1001)
    pkt.time = t0
    pkts.append(pkt)
    # ACK
    t0 += 0.001
    pkt = Ether() / IP(src=a.src, dst=a.dst) / TCP(sport=sport, dport=a.dport, flags="A", seq=1001, ack=2001)
    pkt.time = t0
    pkts.append(pkt)

    # Generate outbound data packets
    out_sent = 0
    chunk_size = 1448  # typical MSS
    seq = 1001
    while out_sent < a.out_bytes:
        chunk = min(chunk_size, a.out_bytes - out_sent)
        t0 += random.uniform(0.001, 0.005)
        pkt = Ether() / IP(src=a.src, dst=a.dst) / \
              TCP(sport=random.randint(40000, 50000), dport=443, flags="PA", seq=seq, ack=2001) / (b"x" * chunk)
        pkt.time = t0
        pkts.append(pkt)
        out_sent += chunk
        seq += chunk

    # Simulate inbound ACKs (small)
    for _ in range(a.in_bytes // 64):
        t0 += random.uniform(0.001, 0.003)
        pkt = Ether() / IP(src=a.dst, dst=a.src) / \
              TCP(sport=443, dport=sport, flags="A", seq=2001, ack=1001 + a.out_bytes) / \
              b""
        pkt.time = t0
        pkts.append(pkt)

    # FIN/ACK closing
    t0 += 0.01
    pkt = Ether() / IP(src=a.src, dst=a.dst) / TCP(sport=sport, dport=a.dport, flags="FA", seq=1001 + a.out_bytes, ack=2001)
    pkt.time = t0
    pkts.append(pkt)

    wrpcap(a.out, pkts)
    print(f"wrote exfil pcap: out={a.out_bytes} bytes, in={a.in_bytes} bytes -> {a.out}")


if __name__ == "__main__":
    main()