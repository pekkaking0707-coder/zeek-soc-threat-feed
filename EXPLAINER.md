# Zeek SOC Threat Feed — Complete Project Explainer
### Streaming Threat Detection for Unidirectional Mirrored Traffic
#### For team presentations, onboarding, and technical documentation — covers concept, architecture, tools, data flow, results

---

## 1. The one-paragraph summary

Banks, power grids, and telecom operators copy all their network traffic into an isolated analysis room using a **one-way link**, so that even if the analysis system is hacked, it physically cannot touch the real network. Our project builds the **AI/ML brain** for that analysis room: a pipeline that reads this one-way traffic stream and detects **six classes of cyberattacks** in near real-time — using only passive observation, never decrypting anything — and outputs structured alerts with confidence scores on a live dashboard.

---

## 2. The problem and why it exists

Critical infrastructure (power plants, telecom, banks) runs on networks that must not be disturbed. Security teams want to monitor this traffic, but a monitoring tool connected to the production network is itself a risk: **if a hacker compromises the monitoring tool, they now have a doorway into the power grid.**

The industry's solution is a **data diode** — a one-way valve for network cables (commercial products: Owl, Waterfall, Fox-IT). Traffic flows from the production network *into* the analysis room, but nothing can ever flow back. The analysis room is called a **monitoring enclave** ("enclave" = isolated, self-contained zone).

Two reasons this design exists:
1. It removes the entire attack class where a compromised analytics system becomes a pivot into the core network.
2. It preserves a clean **chain of custody** — evidence that no one touched the data between capture and analysis, so it holds up in forensics/legal proceedings.

**The trade-off that defines our project:** the analysis system can only *watch*. It cannot send probes, cannot re-query any machine, cannot block anything. Every design decision obeys this **read-only ingest** constraint.

---

## 3. Jargon glossary (every hard term, plainly)

### Networking terms

| Term | Meaning |
|---|---|
| **SPAN / mirror port** | A switch feature that copies all traffic passing through it to another port — a CCTV feed of the network. |
| **Data diode** | Hardware one-way valve for network cables. Data crosses in one direction only, physically. |
| **Monitoring enclave** | The isolated analysis room receiving the one-way copy. |
| **Packet capture (PCAP)** | Full recording of network traffic in a standard file format. |
| **NetFlow / IPFIX / sFlow** | Router accounting summaries instead of full recordings — *who talked to whom, when, how many bytes*. A phone bill vs. a call recording. |
| **TCP handshake (SYN/ACK)** | The 3-message greeting two computers exchange before talking. Requires a reply path — which is why raw TCP cannot cross a one-way link. |
| **DNS** | The internet's phonebook: translates names (google.com) to addresses. Queries are plaintext and visible. |
| **TLS** | The encryption protocol of HTTPS. The *handshake* (greeting) before encryption is visible; the content is not. |
| **QUIC** | Newer encrypted transport (HTTP/3), also has a visible handshake. |

### The six threats we detect

| Class | Threat | Plain-language explanation |
|---|---|---|
| a | **Volumetric / protocol DDoS** | Flooding a server with garbage (SYN floods, UDP floods) so real users can't connect. *Spoofed-source* = attacker fakes sender addresses; caught statistically via **source-IP entropy** (thousands of unique random IPs is abnormal). |
| b | **Botnet C2 beaconing** | Malware inside the network "phones home" to its controller at regular intervals, like a spy checking in every 30 minutes. Detected by measuring gaps between messages (**inter-arrival time, IAT**). Regular gaps = suspicious. |
| c | **DGA + DNS tunneling** | **DGA** (Domain Generation Algorithm): malware rolls dice to invent random domains (`xk29fj2m.xyz`) — blocking lists is useless. **DNS tunneling**: smuggle data out disguised as DNS lookups — like writing secret messages as "house names" on postcards to an accomplice. |
| d | **Malware in encrypted sessions** | Malware hiding inside encrypted connections. We can't (and mustn't) decrypt. But the TLS *handshake* is visible: **JA3/JA4** are fingerprints of that greeting — identifying a burglar by their knock pattern without opening the door. |
| e | **Reconnaissance / port scanning** | An attacker rattling every door handle: probing hundreds of ports to find openings. Detected via **fan-out**: one source touching many distinct destinations in a short window. |
| f | **Data exfiltration** | Stealing data out. Caught by **asymmetric byte ratios**: a machine sending 50× more than it receives is behaving like a leak. |

### Detection / ML terms

| Term | Meaning |
|---|---|
| **Sliding window** | Only look at the last N seconds of events, continuously updated. Makes the system *streaming* (bounded-latency alerts, not an end-of-day report). |
| **Shannon entropy** | A number for "how scrambled is this text." Normal words score low (~1.5–2.8 bits in our measurements); random strings score high (~3.5–4.7). |
| **N-gram model** | Learns which character sequences look "domain-like" vs "random." Trained on the **Tranco list** (top ~1M legitimate domains) as the benign baseline. |
| **KS test** (Kolmogorov–Smirnov) | Statistical test: does this set of timings look like normal traffic, or has its *distribution* shifted? |
| **CUSUM** (cumulative sum) | A change-point detector: accumulates small deviations until confidently declaring "something changed." Cheap, works online — ideal for streaming. |
| **Confidence score** | 0–1 number: how sure the detector is. Computed by fixed, documented formulas per detector. |
| **Severity** | 1–5 danger rating, computed deterministically (see §6). |
| **Hash chain** | Each record embeds the hash of the previous one — any tampering breaks the chain visibly. Tamper-evident log. |
| **Air-gapped** | No internet connection at all. Our LLM runs locally. |
| **LLM hallucination** | When a language model invents facts. Our design makes this harmless (see §6). |

---

## 4. What is used — the complete technology stack

| Tool / tech | Role in project | Why this one |
|---|---|---|
| **Zeek** (v8, Ubuntu VM) | Packet-tier sensor: reassembles conversations, writes dns.log / conn.log / ssl.log | Industry-standard open-source NIDS; C-speed parsing; credible throughput story |
| **goflow2** | Flow-tier collector: NetFlow/IPFIX/sFlow → flow records | Flow records are valid input; single lightweight binary |
| **Python 3** | All detection logic, features, alert engine | Team language; rich scientific stack |
| **Scapy** | Writing labeled synthetic attack PCAPs | Standard packet-crafting library; write-only here (no admin/Npcap needed) |
| **tcpreplay** | Replaying PCAPs onto the wire at controlled speeds | Ask for *demonstrated* Mbps — this is the measurement instrument |
| **pydantic** | Alert schema validation | Enforces the standardized schema in code, not on paper |
| **scipy** | KS-test, CUSUM statistics | Standard, auditable statistical machinery |
| **FastAPI + WebSockets** | SOC dashboard, live alert push | Seconds-scale streaming, tiny code footprint |
| **Ollama + Llama 3.2 3B** | Local (air-gapped) LLM alert narration | No cloud, no exceptions — matches the enclave's no-connectivity reality |
| **VirtualBox + Ubuntu 22.04 VM** | Isolated lab environment | Reproducible testbed on student laptops |
| **Linux network namespaces + veth pair** | Attacker/target virtual networks inside one VM | A virtual "cable" we can legitimately monitor; no second machine needed |
| **hping3, slowhttptest, nmap, iperf3, dnscat2, DGArchive samples** | Attack traffic generators | We generate exactly what the threat model prescribes |
| **Tranco list** | Benign domain baseline for DGA training | Public, citable legitimate-domain ranking |
| **SHA-256 hash chain** | Forensic chain of custody | Tamper-evident alert log |

---

## 5. How it works — follow one attack through the system

Real verified example from our testbed (a DNS-tunneling attack):

**Step 1 — Attack is generated.** Our generator (`gen_dns_tunnel.py`) creates 50 DNS queries. Each query's *name* carries a base32-encoded chunk of stolen data: `ab12cd34....tunnel.evil-c2.example`. Saved as a labeled PCAP file.

**Step 2 — Replayed onto the wire.** `tcpreplay` blasts the PCAP through the virtual cable (veth pair) at a measured rate — in our verified run: 50 packets, 55 Mbps burst, 0 failures.

**Step 3 — Zeek observes.** Zeek passively captures and writes `dns.log` — one row per query: timestamp, source IP, the full QNAME, record type (TXT). No decryption, no contact with the sender.

**Step 4 — Streaming feature extraction.** Our parser tails the log row-by-row (no batch passes). For each query we compute, inside a 60-second sliding window per client: max label entropy (3.75 bits), longest label (16 chars), TXT-record ratio (1.0), queries/sec.

**Step 5 — Detection.** Two detectors consume these features:
- *Tunnel detector*: TXT-ratio ≥ 0.6 → fires at confidence 0.75.
- *DGA detector*: composite entropy+length+digit score — suppressed here by tunnel-priority logic (the more specific diagnosis wins; keeps evaluation classes clean).

**Step 6 — Alert is emitted** (real output from our verified run):
```json
{"timestamp": "2026-08-23T18:32:51Z",
 "flow_id": "10.200.0.70->10.200.0.1#dns",
 "threat_class": "dns_tunneling",
 "confidence_score": 0.75, "severity": 2,
 "briefing_status": "pending",
 "supporting_evidence": [
   {"feature": "qname_max_len", "value": 76, "threshold": 120.0},
   {"feature": "txt_ratio", "value": 1.0, "threshold": 0.6},
   {"feature": "qps", "value": 1.65}]}
```

**Step 7 — Dashboard.** The alert is pushed over a WebSocket to the browser — it appears in the severity-colored table within seconds (deterministic detection is instant; nothing waits for the LLM).

**Step 8 — LLM briefing (async).** The local LLM receives the alert JSON and writes an analyst briefing where every claim must cite an evidence ID — `[EV:0]`, `[EV:1]` — a validator strips any uncited sentence. If the model fails, a deterministic template briefing is attached instead (`briefing_status: template`). The system degrades, never silences, and can never invent severity.

**The same flow applies to all six threat classes** — only the features and detector change.

---

## 6. The scoring system — every number has a stated rule

- **Confidence (0–1):** each detector computes it from its own features — e.g., how far past a threshold the measurement sits, or a trained model's probability. Mapping documented per detector in `docs/models.md`. Never hand-assigned, never from the LLM.
- **Severity (1–5):** `floor(base_severity × confidence + 0.5)`, where base severity is a fixed lookup per class: exfiltration = 5, encrypted-malware & beaconing = 4, floods/DNS attacks/DGA = 3, port scan = 2. One-line explainable — the answer to "is severity an AI guess?" is *no, and here is the formula*.
- **Hash chain (chain of custody):** every alert stores SHA-256 of its evidence plus the previous alert's hash. Tampering with any record breaks the chain visibly — directly implementing the forensic requirement.

**Why severity must NOT come from the LLM:** in critical infrastructure, a probabilistic model must never decide how dangerous an alert is. Rules are auditable; hallucinations are not.

---

## 7. The testbed — how we simulate the enclave on laptops

```
        attacker namespace                target namespace
      ┌──────────────────┐            ┌──────────────────────┐
      │ hping3 / nmap /  │   veth     │ Zeek -i veth-t       │
      │ tcpreplay /      │ ══════════ │ (passive monitor)    │
      │ scapy replays    │  pair      │ target services      │
      │ 10.200.0.1       │            │ 10.200.0.2           │
      └──────────────────┘            └──────────────────────┘
```

- **Network namespaces**: a Linux feature creating isolated virtual networks inside one machine — our "attacker" and "target" can't see each other except through the virtual cable.
- **veth pair**: a virtual Ethernet cable between the two namespaces.
- Zeek monitors the target-side end of the cable — exactly like a real mirror port, but reproducible on any laptop.

---

## 8. Current status — built and verified (real numbers)

| Milestone | Status |
|---|---|
| Windows host: detectors, dashboard, local LLM | ✅ installed & smoke-tested |
| Ubuntu VM: Zeek + attack tools + veth topology | ✅ live capture verified |
| Live loop: replay → Zeek → TSV → detection → alert | ✅ verified in VM (3/3 replays detected) |
| Detector: DNS family — benign | ✅ **0 false alarms** |
| Detector: DNS family — DGA mix | ✅ detected @ conf 0.61–0.69 |
| Detector: DNS family — tunneling | ✅ detected @ conf 0.75, zero cross-class confusion |
| Detector: port scan | ✅ detected at threshold; benign datasets → 0 alerts |
| Detector: beaconing | ✅ conf 1.0, sev 4; 0 FP on benign/DGA |
| Detector: floods (SYN/UDP, spoofed) | ✅ 1 alert @ conf 1.0, entropy 8.97/9.64 |
| Labeled traffic generators (all 6 classes) | ✅ built, PCAPs in `datasets/` |
| Alert schema + severity formula + hash chain | ✅ implemented & unit-verified |
| Next | exfiltration (f) → encrypted-malware (d) → benchmarks |

---

## 9. Evaluation plan — how we prove it works

Three measurable things:

1. **Precision / recall per threat class** — replay each labeled attack PCAP mixed with benign background; count hits, misses, false alarms. Ground truth = generator filename.
2. **Demonstrated throughput** — replay at increasing speeds (10 → 25 → 50 → 100 Mbps…) until packets drop or latency breaks; report the highest sustained rung with Zeek's own drop statistics.
3. **Bounded latency** — p50/p95 seconds from packet timestamp to dashboard appearance; planning SLA ≤ 5 s, but we **report whatever we measure** — never the target.

All numbers land in `docs/validation.md` alongside the model documentation (`models.md`, `features.md`).

---

## 10. Design decisions to defend (the five "why" questions)

1. **Why no decryption?** Constraint — and unnecessary: metadata (fingerprints, sizes, timing, DNS names) carries enough signal.
2. **Why is severity not from the AI?** A probabilistic model must never decide how dangerous an alert is in critical infrastructure; formulas are auditable.
3. **Why both packet AND flow tiers?** Flow records are cheap and scalable but contain no DNS names or TLS fingerprints — classes (c) and (d) *structurally require* packets. Stating this preempts the sharpest technical question.
4. **Why is the LLM asynchronous?** Alerts fire instantly from the deterministic layer; the briefing attaches seconds later. The LLM can never add latency to detection.
5. **Why synthetic traffic?** Real one-way-link attack data isn't public; labeled ground truth enables honest precision/recall.

---

## 11. Rapid-fire Q&A

- **"What if the attacker uses DNS-over-HTTPS?"** → Stated limitation: DNS features degrade; flow/timing/volume features persist. Disclosed, not hidden.
- **"Can your own system become the pivot?"** → No — it makes zero outbound connections by construction: local models, local LLM, local dashboard.
- **"If traffic is one-way, how do you compute in/out byte ratios?"** → "Unidirectional" is the copy path *into* the enclave; the mirror captures both directions of production conversations.
- **"How do you know your thresholds are right?"** → Calibrated empirically on labeled data (we measured entropy distributions before choosing values), and the n-gram model replaces the heuristic next iteration.
- **"What happens when the LLM hallucinates?"** → It can't do damage: severity/confidence are pre-computed, every claim must cite evidence IDs, uncited text is stripped, and failure falls back to templates.
- **"Why does the enclave need a diode if it isn't classified?"** → It protects the *production* network from a compromised analytics platform, and preserves forensic chain of custody.

---