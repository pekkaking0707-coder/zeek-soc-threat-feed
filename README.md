# Zeek SOC Threat Feed & Analytics Dashboard

A streaming, read-only threat-detection pipeline for mirrored network traffic. Ingests Zeek logs (pcap/NetFlow/IPFIX) and detects six threat classes in near real-time — DDoS floods, C2 beaconing, DGA/DNS tunneling, encrypted-session malware, reconnaissance, and data exfiltration — with deterministic alerts, severity scoring, hash-chained forensic logs, and an async air-gapped LLM triage layer.

## Architecture Overview

```
[ Network Mirror / Diode ] → [ Zeek / goflow2 Ingest ] → [ Feature Extraction ]
                                                          │
                    ┌─────────────────────────────────────┼─────────────────────────────────────┐
                    ▼                                     ▼                                     ▼
            [ DNS Family Detectors ]              [ Flow Detectors ]                      [ TLS Detectors ]
            • DGA domains (entropy/n-gram)           • SYN/UDP floods (rate+entropy)         • JA3/JA4 fingerprinting
            • DNS tunneling (TXT/NULL ratios)        • Slowloris (low-byte concurrency)      • Packet-size/timing sequences
            • QNAME entropy/length                                              • Spoofed-source entropy
                    │                                     │                                     │
                    └─────────────────────────────┬─────────────────────────────┘
                                                  ▼
                                    [ Detection Engine ]
                                    • Deterministic thresholds
                                    • KS-test / CUSUM statistical models
                                    • Trained n-gram DGA classifier
                                    • Severity + confidence (deterministic)
                                                  ▼
                                    [ Alert Engine ]
                                    • Standardized JSON schema
                                    • Dedup (host, rule, window)
                                    • Append-only hash-chained log
                                                  ▼
                                    [ LLM Triage (async) ]
                                    • Local quantized model (Ollama)
                                    • Citation-constrained narrative
                                    • Template fallback on failure
                                                  ▼
                                    [ SOC Dashboard ]
                                    • FastAPI + WebSocket live view
                                    • Severity-colored alert table
                                    • Briefing attachment (async)
```

## Key Features

- **Six threat detectors** — DDoS floods, C2 beaconing, DGA/DNS tunneling, encrypted-session malware, port scanning, data exfiltration
- **Dual-tier ingest** — Zeek (packet-tier: DNS, TLS, full packets) + goflow2/pmacct (flow-tier: NetFlow/IPFIX/sFlow)
- **Deterministic detection** — All confidence/severity computed by rules/statistics, never by LLM
- **Streaming with bounded latency** — Alerts raised incrementally; LLM briefing attaches asynchronously
- **Forensic chain of custody** — Append-only alert log with SHA-256 hash chain
- **Air-gapped LLM triage** — Local Ollama model; citation-constrained; template fallback on failure
- **Live SOC dashboard** — FastAPI + WebSockets; real-time alert streaming; severity-colored table
- **Synthetic traffic generators** — Labeled PCAPs for all 6 threat classes (hping3, nmap, dnscat2, DGArchive, etc.)

## Quickstart

```bash
# 1. Install dependencies
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2. Start local LLM (Ollama)
ollama serve & ollama pull llama3.2:3b

# 3. Run Zeek on a live interface or replay PCAPs
zeek -i <interface> local

# 4. Run detectors (examples)
python run_dns_detection.py --zeek-log /path/to/dns.log --follow
python run_portscan_detection.py --zeek-log /path/to/conn.log --follow
python run_beaconing_detection.py --zeek-log /path/to/conn.log --follow
python run_floods_detection.py --zeek-log /path/to/conn.log --follow

# 5. Launch dashboard
uvicorn dashboard.main:app --port 8080
# Open http://localhost:8080
```

## Detectors Implemented

| Threat Class | Detector | Method | Data Source |
|-------------|----------|--------|-------------|
| **DDoS Floods** (a) | `syn_flood`, `udp_flood`, `slowloris` | Rate thresholds + source-IP entropy | Flow (conn.log) |
| **C2 Beaconing** (b) | `beaconing` | KS-test + CUSUM on IAT series | Flow (conn.log) |
| **DGA Domains** (c) | `dga_domain` | Entropy + n-gram scoring | Packet (dns.log) |
| **DNS Tunneling** (c) | `dns_tunneling` | TXT/NULL ratio, QNAME entropy/length | Packet (dns.log) |
| **Encrypted Malware** (d) | `encrypted_malware` | JA3/JA4 fingerprinting + timing | Packet (ssl.log) |
| **Port Scan** (e) | `port_scan` | Fan-out distinct dst ports/hosts | Flow (conn.log) |
| **Data Exfiltration** (f) | `data_exfiltration` | Outbound:inbound byte ratio | Flow (conn.log) |

## Project Structure

```
zeek-soc-threat-feed/
├── alerts/           # Alert schema (pydantic), severity rules, hash chain
├── detectors/        # Six threat detectors
├── features/         # Windowing / feature helpers
├── ingest/           # Zeek TSV parser + follower (live tail)
├── triage/           # Air-gapped LLM narration + template fallback
├── dashboard/        # FastAPI + WebSocket live view
├── generators/       # Labeled synthetic traffic per threat class
├── benchmarks/       # Throughput ladder + latency percentiles
├── datasets/         # Labeled PCAPs (gitignored)
├── docs/             # Models, features, validation docs
├── benchmarks/       # Throughput/latency measurement scripts
├── scripts/          # Build scripts (PDF generation)
├── requirements.txt
├── .gitignore
├── README.md
├── PLAN.md           # Architecture & design decisions
├── BUILD_GUIDE.md    # Environment setup & phased build
└── EXPLAINER.md      # Detailed project explainer
```

## Documentation

- **[PLAN.md](PLAN.md)** — Architecture, threat models, detector specs, severity rules, compliance checklist
- **[BUILD_GUIDE.md](BUILD_GUIDE.md)** — Environment setup, VM networking, phased build plan
- **[EXPLAINER.md](EXPLAINER.md)** — Detailed project walkthrough, data flow, tech stack

## Requirements

- Python 3.10+
- Zeek (for packet-tier logs)
- goflow2 or pmacct (for flow-tier)
- Ollama + local LLM (e.g., `llama3.2:3b`)
- Linux (for Zeek capture/tcpreplay) — Windows supported for dev/dashboard only

## License

MIT License — see [LICENSE](LICENSE) for details.