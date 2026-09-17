# Ingest — Dual-Tier (PLAN §4 Stage 0)

## Packet tier — Zeek (REQUIRED for detectors c & d)

```bash
# Live capture on the monitor interface (VM: veth-t; two-laptop: mirror-fed iface)
zeek -i veth-t local
# Logs land in ./conn.log ./dns.log ./ssl.log (or /opt/zeek/logs/current/)
```

JA4 acquisition — decide once, hour 0:
- Option A: FoxIO JA4 Zeek package (`zkg install foxio/ja4`) → ja4 in ssl.log
- Option B: compute JA4 in Python from ssl.log handshake fields (version,
  ciphers, extensions, ALPN) per the JA4 spec — no plugin dependency

Feature mapping (docs/features.md owns the full table):

| Zeek log | Feeds detectors |
|---|---|
| dns.log (qname, qtype, rtt) | c: DGA + tunnelling |
| conn.log (duration, bytes, orig/resp pkts) | a, e, f + b (IAT from ts) |
| ssl.log (server_name, ja3/ja3s, ja4) | d |
| stats.log (capture loss) | throughput benchmark reporting |

## Flow tier — goflow2 (NetFlow/IPFIX/sFlow backbone; feeds a/b/e/f)

```bash
# Exporter side (softflowd turns the replay interface into NetFlow v9):
sudo apt install softflowd
sudo softflowd -i veth-t -n 127.0.0.1:2055

# Collector side:
goflow2 -transport.file flows.csv -listen netflow://:2055
```

The collector's records normalize into the same feature keys the detectors
consume (features/windowing.py). PS compliance: both PCAP and flow-record
ingest paths demonstrated.
