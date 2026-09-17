# Synthetic Traffic Generators — labeled captures per PS threat class (PLAN §8)

Each generator writes a labeled PCAP under `datasets/`; the filename is the
ground-truth label for evaluation runs. Benign background is layered on top
during evaluation (iperf3 capture or replay mixing).

## Python generators (run anywhere; write-only — no Npcap/admin needed)

| Class | Script | Notes |
|---|---|---|
| b beaconing | `gen_beaconing.py` | jitter-controlled periodicity |
| c DGA | `gen_dga_queries.py` | entropy + ratio controls |
| c DNS tunnelling | `gen_dns_tunnel.py` | dnscat2-style base32 TXT framing |
| e port scan | `gen_portscan.py` | fan-out across N distinct dst ports |

```bash
python generators/gen_beaconing.py --jitter-pct 3 --beacons 60 --out datasets/beaconing.pcap
python generators/gen_dga_queries.py --dga-ratio 0.5 --out datasets/dga_queries.pcap
python generators/gen_dns_tunnel.py --queries 80 --out datasets/dns_tunneling.pcap
python generators/gen_floods.py --type syn --spoofed --packets 5000 --out datasets/syn_flood_spoof.pcap
python generators/gen_portscan.py --ports 100 --out datasets/port_scan.pcap
```

## Tool-based classes (run inside the Ubuntu VM — see BUILD_GUIDE §4 topology)

| Class | Tool | Recipe |
|---|---|---|
| a SYN/UDP floods | hping3 | `sudo hping3 -S --flood -p 80 <tgt>` · `sudo hping3 --udp --flood -p 53 <tgt>` |
| a slowloris | slowhttptest | `slowhttptest -c 1000 -H -i 10 -r 200 -u http://<tgt> -l 300` |
| e recon/port scan | nmap | `nmap -sT -T4 -p- <tgt>` (TCP connect: no handshake completion by *us* — we observe the scan traffic passively) |
| f exfiltration | iperf3 / scp | reverse mode bulk upload: `iperf3 -c <tgt> -R -t 300` from inside; or `scp bigfile user@<tgt>:` |
| d TLS fingerprint diversity | curl / openssl | `curl -s https://<tgt>` vs `openssl s_client -connect <tgt>:443` differ in JA4; QUIC client for JA4-QUIC coverage |

Replay everything through tcpreplay at controlled rates:

```bash
tcpreplay-edit --intf1=veth-t --topspeed datasets/dns_tunneling.pcap
tcpreplay-edit --intf1=veth-t --mbps=50   datasets/mixed_eval.pcap   # throughput ladder rung
```

Merge benign + attack into an evaluation mix:

```bash
mergecap -w datasets/mixed_eval.pcap benign.pcap dns_tunneling.pcap beaconing.pcap port_scan.pcap
```
