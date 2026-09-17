# Zeek SOC Threat Feed — Architecture & Design Decisions
### v4.1 — Streaming Threat Detection for Unidirectional Mirrored Traffic

> **v4.1 changelog:** severity rule defined; throughput reframed as target-to-validate; true ~20-second pitch added; schema example made consistent with severity formula; `confidence_score` provenance defined; flow-tier "primary" overclaim corrected (QNAMEs and JA4 exist only in packet-tier data); LLM template-failure path restored with `briefing_status` enum extended; alert-latency SLA planning target added; JA4 acquisition path flagged; banker's-rounding footnote on severity formula.

---

## 1. Elevator Pitch

**Full version (~30 sec):**

> "Network operators mirror gateway and peering traffic one-way into an isolated analysis enclave — so even if the analysis system is compromised, it has no path back into the production network, and every alert keeps a clean forensic chain of custody. We ingest that read-only feed — packet captures and flow records — and detect DDoS floods, botnet beaconing, DGA and DNS tunneling, malware inside encrypted TLS/QUIC sessions, reconnaissance, and data exfiltration — streaming alerts with bounded latency, zero payload decryption, and every claim traceable to raw evidence."

**Tight version (~20 sec):**

> "Operators mirror gateway traffic one-way into an isolated enclave, so even a compromised analytics system can't reach back into production. We ingest that read-only feed and detect DDoS, C2 beaconing, DNS tunneling, encrypted-session malware, recon, and exfiltration — streaming, bounded-latency alerts, zero decryption, every claim traceable to evidence."

---

## 2. Threat Model & Deployment Context

- **Direction:** production traffic (gateway/peering links) → [passive mirror or hardware diode, one-way] → monitoring enclave, where the pipeline runs. The enclave cannot send anything back.
- **Why the diode exists:** protects the production network from a compromised monitoring/analytics platform, and preserves an unmodified evidence trail for forensics.
- **Tap placement:** a mirror-fed analysis system never completes a handshake or sends anything — it observes a passive copy of already-live bidirectional conversations. This is how Zeek, Suricata, and Snort have always operated.
- **Direction-dependency note (class f):** outbound:inbound byte ratios assume the mirror copies *both directions* of production conversations into the enclave. "Unidirectional" describes the copy-to-enclave path, not the underlying traffic.
- **Scope:** "critical-infrastructure operators" and "gateway and peering links" — not "classified" or "military." The pattern generalizes to any mirrored-link monitoring (ISP peering, enterprise egress, data centers).
- **Air-gapped requirement:** the intelligence layer in the enclave has no ability to probe or push commands, implying no assumed external connectivity. Local LLM inference only, no cloud, no exceptions — including development (iterate prompts on synthetic data only).

---

## 3. Pipeline Architecture

```
[ Production network — gateway / peering links ]
                    │  (live, bidirectional, normal traffic)
                    ▼
    ┌────────────────────────────────────┐
    │ Passive Mirror / Hardware Diode     │  One-way copy only.
    │ (SPAN port or optical tap)          │  No return path exists.
    └───────────────────┬────────────────┘
                    │
                    ▼           MONITORING ENCLAVE (isolated, air-gapped)
    ┌────────────────────────────────────┐
    │ Stage 0: Dual-Tier Ingest           │
    │  • Flow tier (scalable backbone):   │  goflow2 / pmacct → NetFlow/
    │    NetFlow/IPFIX/sFlow               │  IPFIX/sFlow records
    │  • Packet tier (deep inspection —   │  Zeek → conn/dns/ssl logs,
    │    REQUIRED for detectors c & d):    │  stream reassembly, JA3/JA4
    └───────────────────┬────────────────┘
                    │
                    ▼
    ┌────────────────────────────────────┐
    │ Stage 1: Per-Threat Feature         │  See Section 6 mapping table
    │ Extraction                          │  (a–f, one path each)
    └───────────────────┬────────────────┘
                    │
                    ▼
    ┌────────────────────────────────────┐
    │ Stage 2: Detection Engine           │  Deterministic thresholds +
    │                                      │  KS-test / CUSUM statistical
    │                                      │  detectors + JA3/JA4 matching.
    │                                      │  Confidence + severity computed
    │                                      │  HERE (Section 5 rules).
    └───────────────────┬────────────────┘
                    │  raises alert immediately — satisfies bounded latency
                    ▼
    ┌────────────────────────────────────┐
    │ Stage 3: Alert Engine               │  Standardized schema (Sec 5),
    │                                      │  dedup by (host, rule, window),
    │                                      │  append-only hash-chained log
    └───────────────────┬────────────────┘
                    │  async — never gates alert delivery
                    ▼
    ┌────────────────────────────────────┐
    │ Stage 4: Air-Gapped LLM Triage      │  Local quantized model. Every
    │ (no cloud, no exceptions)           │  factual claim cites a
    │                                      │  supporting_evidence id.
    │                                      │  Severity/confidence narrated,
    │                                      │  never invented, by the LLM.
    │                                      │  On failure/timeout: template
    │                                      │  briefing, never silence.
    └───────────────────┬────────────────┘
                    │
                    ▼
    ┌────────────────────────────────────┐
    │ Stage 5: SOC Dashboard              │  FastAPI + WebSockets.
    │                                      │  Alert (severity + confidence)
    │                                      │  appears instantly; briefing
    │                                      │  attaches seconds later.
    └───────────────────┬────────────────┘
```

**Tier dependencies:** detectors (c) and (d) structurally require the packet tier — DNS QNAMEs and TLS fingerprints do not exist in NetFlow/IPFIX flow records. Detectors (a), (e), (f) are flow-native. Detector (b) runs on either (conn.log inter-arrivals or flow-record timestamps). The flow tier is the scalable backbone, not a standalone solution.

---

## 4. Alert Schema (exact fields)

```json
{
  "timestamp": "2026-08-22T14:03:11Z",
  "flow_id": "10.2.4.17:51322->10.2.4.1:443#tcp",
  "threat_class": "encrypted_malware",
  "confidence_score": 0.93,
  "severity": 4,
  "briefing_status": "pending",
  "supporting_evidence": [
    { "feature": "ja4_hash", "value": "q13d0313h3_...", "matched_list": "known_malicious" },
    { "feature": "packet_size_seq_dev", "value": 3.9, "threshold": 3.0 }
  ]
}
```

*Example is self-consistent with the severity rule below: base 4 × 0.93 → floor(3.72 + 0.5) = 4.*

### Severity Scale

| Severity | Meaning |
|---|---|
| 5 | Critical |
| 4 | High |
| 3 | Medium |
| 2 | Low |
| 1 | Informational |

**Base severity per `threat_class`:** `data_exfiltration` = 5, `encrypted_malware` / `beaconing` = 4, `syn_flood` / `udp_flood` / `slowloris` / `dns_tunneling` / `dga_domain` = 3, `port_scan` = 2.

**Final severity** = `floor(base_severity × confidence_score + 0.5)`, clipped to [1, 5]. *(Python's `round()` uses banker's rounding — use `floor(x + 0.5)` for half-up behavior.)*

**Confidence score:** produced by each detector's own scoring function — normalized feature deviation beyond threshold for statistical detectors, model output probability for trained ones (e.g., DGA classifier). Exact mappings and calibration per detector are documented in `/docs/models.md`. Never hand-assigned; never generated by the LLM.

**Optional escalation:** if two distinct `threat_class` alerts share an endpoint within a short window, bump the later alert's severity by 1, capped at 5.

**Briefing lifecycle:** `briefing_status`: `pending → ready` (LLM narrative attached) or `pending → template` (LLM failed/timed out — deterministic fallback briefing attaches instead; the pipeline degrades, never silences).

---

## 5. Complete Threat-Category Mapping (a–f)

| Cat | Threat | `threat_class` | Detection technique | Data source |
|---|---|---|---|---|
| a | DDoS / floods | `syn_flood`, `udp_flood`, `slowloris` | Flow-level rate thresholds + source-IP Shannon entropy (spoofed-source floods) | hping3, Slowloris; benign baseline via iperf3/Ostinato |
| b | Botnet C2 beaconing | `beaconing` | KS-test (distributional shift) + CUSUM (drift/change-point) on IAT series per (src,dst); flag low-variance, high-regularity flows toward a small destination set | Sandboxed C2 emulator for realistic beaconing timing |
| c | DGA / DNS tunneling | `dga_domain`, `dns_tunneling` | Entropy + n-gram scoring on DNS QNAME (plaintext); query-length distribution; unusual record types (TXT/NULL). **Packet tier required** | dnscat2/iodine, DGArchive samples; benign QNAMEs from Tranco list |
| d | Malware in encrypted sessions | `encrypted_malware` | JA3/JA3S (TLS/TCP) + JA4 (QUIC) fingerprint extraction; match against known-good client-fleet whitelist and/or public malicious-JA3 reference lists (e.g. abuse.ch); packet-size/timing-sequence classifier. **Packet tier required** | Vary TLS client tools (curl, openssl s_client) for fingerprint diversity; QUIC-capable client for JA4 coverage |
| e | Reconnaissance / port scanning | `port_scan` | Fan-out counter: distinct (dst_ip, dst_port) pairs contacted by one source within a sliding window; threshold or entropy-based flag | nmap against a lab target range |
| f | Data exfiltration | `data_exfiltration` | Per-host outbound:inbound byte-ratio from flow records; flag sustained outbound bias inconsistent with baseline | iperf3 configured for large one-directional transfer, or scp/rsync of a large file |

---

## 6. Architectural Constraints — Compliance Checklist

| Constraint | How this design satisfies it |
|---|---|
| (a) Read-only ingest, no return path, no inline block | Passive mirror/diode input only; no active-mitigation capability. Dashboard action column is "recommended human response," never automated. |
| (b) No payload decryption | Stage 1 never decrypts TLS/QUIC. Encrypted-session detection uses JA3/JA3S/JA4 + size/timing metadata only. |
| (c) Streaming, not batch | Stage 2's deterministic detectors process incrementally and raise alerts immediately; LLM narrative attaches asynchronously without gating delivery. **Internal SLA: p95 alert latency ≤ 5 s.** |
| (d) Defined, demonstrated throughput | **Internal planning target — validate, don't pre-claim:** ~100 Mbps / ~500 flows/sec on demo hardware. Report measured sustained number with drop rate and alert-latency p50/p95. |
| (e) Standardized alert schema | Section 4, verbatim field names — including severity and confidence, each with a stated computation rule. |

---

## 7. Evaluation & Benchmarking

**Primary (synthetic path, no external dataset dependency):**
- Benign background: iperf3 / Ostinato (TRex optional if DPDK NIC available).
- Per `threat_class`, use the tool/technique in the mapping table.
- Report precision, recall, and false-positive rate per class, plus measured throughput/latency numbers.

**Bonus / stretch only:** ICS-specific validation (Modbus/DNP3) — optional polish, never the core claim. If built, disclose the allowlist provenance.

---

## 7. Forensic Chain of Custody

- Append-only alert log.
- Each alert record stores a hash of its own `supporting_evidence` plus the hash of the previous record (simple hash chain).
- Directly answers "how do you preserve chain of custody."

---

## 8. Non-Negotiables

- No cloud LLM anywhere, including development — air-gapped only.
- No automated blocking or return-path action anywhere in the system.
- "Streaming" = bounded-latency deterministic alerts; the LLM briefing is async and never gates delivery; LLM failure degrades to template briefing, never silence.
- Every LLM-generated claim cites a `supporting_evidence` id; uncited claims stripped by a post-processing validator before display.
- Severity AND confidence computed deterministically in Stage 2 by the Section 5 rules; narrated, never generated, by the LLM.
- Don't state a throughput or latency number in writing until it's actually been measured.

---

## 9. Environment & Build Order

**Hour 0–2 — environment first (critical path):**
- Linux required: Zeek, goflow2, hping3 do not run reliably on Windows. Ubuntu VM or two laptops (one replays via tcpreplay, one captures/analyzes). WSL2 raw-socket capture is unreliable.
- Verify end-to-end capture path before any detector work: tcpreplay a sample pcap → Zeek produces conn/dns/ssl logs.
- Repo scaffolded with `/docs` stubs and the alert schema module.
- Decide JA4 acquisition: FoxIO JA4 Zeek plugin, or compute JA4 from ssl.log handshake fields in Python.

**Roles:** infra/capture+replay · traffic generators (start hour 0) · detectors/ML · LLM+dashboard.

**Detector build order (easiest wins first):** c (DNS family shares one QNAME pipeline) → e (fan-out counter, trivial) → b (KS/CUSUM machinery, reused by d) → a (rate + entropy thresholds; parallelizable with c/e) → f (byte-ratio baselines) → d (JA4 extraction + matching) → LLM triage → throughput/latency benchmark run.

**Slide-only (disclose as partial):** full JA3/JA4 reference-list integration, full precision/recall sweep, ICS bonus layer, TRex.

---

## 10. Documentation Deliverables

- `/docs/models.md` — every model and scoring function: DGA n-gram scorer (features, training set: DGArchive-style vs Tranco benign, confusion matrix), beaconing KS/CUSUM parameters, threshold tables, each detector's confidence-scoring function and calibration, the severity-scale rule, JA3/JA4 whitelist/blacklist sources.
- `/docs/features.md` — feature dictionary with per-detector mappings (a–f) and tier dependency (packet vs flow).
- `/docs/validation.md` — labeled capture methodology, train/validation splits, per-class precision/recall/F1, throughput and latency measurement method and actual measured results.

---

## 11. What Changed (self-check log)

| Issue | Status |
|---|---|
| Direction of monitoring (production → enclave) | Corrected — grounded in standard passive monitoring architecture |
| Threat classes d, e, f missing from enum | Filled in |
| JA4/QUIC coverage | Added |
| Beaconing validation vs ICS replay contradiction | Fixed — use C2 emulator |
| Tap-placement "paradox" over-dramatized | Simplified — standard passive NIDS behavior |
| "Classified enclave" language | Recalibrated to critical-infrastructure operators |
| Severity missing from alert schema | Fixed — Section 4 |
| `dga_beaconing` misleading class name | Renamed `dga_domain` |
| Documentation had no owner | Added — Section 10 |
| No environment/build-order plan | Added — Section 9 |
| TRex infeasible on plain laptops (DPDK NICs) | Marked optional |
| Class (f) direction-dependency implicit | Stated explicitly |
| Throughput target stated as pre-achieved before testing | Reframed as target-to-validate |
| Severity rule asserted but never defined | Explicit scale + formula added |
| Pitch exceeded ~55-word ask | Genuine ~20-second alternative added |
| Schema example violated severity formula | Fixed — example now self-consistent |
| `confidence_score` provenance undefined | Defined — per-detector scoring functions |
| "Flow tier primary" overclaim | Corrected — tier dependencies explicit |
| LLM failure path dropped | Restored — template fallback + `ready | template` status |
| Constraint (c) had no defined latency bound | Planning SLA added — p95 ≤ 5 s |
| JA4 not native to Zeek; acquisition undecided | Flagged — FoxIO plugin or compute from ssl.log |
| Python `round()` banker's-rounding trap in severity formula | Footnoted — use floor(x+0.5) |

---

## 12. Anticipated Questions

- *"Why does the monitoring enclave need a diode at all?"* → It protects the production network from a compromised analytics platform, and preserves forensic chain of custody.
- *"You said no payload decryption — how do you catch malware in encrypted sessions?"* → JA3/JA3S/JA4 fingerprints plus packet-size/timing-sequence analysis, entirely from handshake and flow metadata.
- *"What's your throughput?"* → Cite the measured number directly — never the planning target.
- *"How do you detect exfiltration/recon/encrypted-malware?"* → Standard equivalents (nmap, asymmetric iperf3/scp, varied TLS/QUIC clients) — documented in the mapping table.
- *"Doesn't the LLM add latency you're not allowed?"* → No — the deterministic alert, with severity and confidence, fires immediately; the briefing attaches asynchronously via `briefing_status`, and if the LLM fails entirely, a template briefing attaches instead.
- *"How are severity and confidence computed?"* → Both deterministic: severity is a base-per-class lookup scaled by confidence, clipped 1–5; confidence comes from each detector's documented scoring function. The LLM only narrates the numbers, never sets them.
- *"If flow records lack QNAMEs and TLS fingerprints, how do flow-only deployments work?"* → They cover classes a/b/e/f; classes c and d require the packet tier by nature — our dual-tier design makes all six possible, and we state which tier feeds which detector.
- *"Can your own system become the pivot the background warns about?"* → Zero outbound connections by construction: local models, local LLM, local dashboard.

---

## 13. Tech Stack Summary

- **Flow tier:** goflow2 or pmacct (NetFlow/IPFIX/sFlow collection)
- **Packet tier:** Zeek (stream reassembly, DNS/SSL logs, JA3 script); JA4 via FoxIO Zeek plugin or computed from ssl.log handshake fields
- **Synthetic traffic:** iperf3, Ostinato (TRex optional — needs DPDK NIC), hping3, Slowloris, dnscat2/iodine, DGArchive samples, sandboxed C2 emulator, nmap, scp/curl/openssl for fingerprint diversity
- **Detection:** Python (KS-test/CUSUM via scipy, entropy/n-gram scoring, fan-out counters)
- **LLM triage:** local quantized model via Ollama (e.g. Llama 3), citation-constrained prompt + post-processing validator + deterministic template fallback
- **Dashboard:** FastAPI + WebSockets