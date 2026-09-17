# validation.md — training & validation approach (PLAN §12)

- Labeled capture methodology: generators/ per class, filename = label
- Benign background: iperf3 bulk + scripted web/DNS; mixing recipe in generators/README.md
- Splits: per-class PCAPs split train/calibration/eval (record ratios here)
- Per-class results table: precision / recall / F1 / FPR (fill after runs)

| threat_class | precision | recall | F1 | FPR |
|---|---|---|---|---|
| syn_flood | | | | |
| udp_flood | | | | |
| slowloris | | | | |
| beaconing | | | | |
| dga_domain | | | | |
| dns_tunneling | | | | |
| encrypted_malware | | | | |
| port_scan | | | | |
| data_exfiltration | | | | |

- Throughput: measured sustained Mbps / flows/sec + drop rate (stats.log) + method
- Latency: p50/p95 from benchmarks/latency_measure.py + method
- Rule: report measured numbers only — never planning targets (PLAN §10)
