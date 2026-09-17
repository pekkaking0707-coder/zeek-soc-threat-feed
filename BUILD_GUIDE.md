# Zeek SOC Threat Feed — Build Guide
### Companion to PLAN.md v4.1 — environment, topology, phased build

---

## 1. Hardware & Host Requirements

| Item | Minimum | Recommended |
|---|---|---|
| Host laptop RAM | 8 GB | 16 GB (7B LLM + VM comfortably) |
| Disk free | 40 GB | 60 GB (Ubuntu VM + pcaps + model) |
| Virtualization | VirtualBox or Hyper-V enabled | — |
| Second machine | not required | optional later for wire-rate throughput |

Roles split: **Windows host** = detectors development, dashboard, local LLM.
**Ubuntu VM** = Zeek capture, tcpreplay replay, attack tools (hping3, nmap,
slowhttptest, iodine, dnscat2), goflow2.

---

## 2. Windows Host Setup

```powershell
cd <project-root>
powershell -ExecutionPolicy Bypass -File setup_windows.ps1
```

What it does: installs `requirements.txt` into your Python, starts the Ollama
service if needed, pulls `llama3.2:3b` (~2 GB, CPU-friendly), and smoke-tests
the alert schema + template briefing.

Known traps:
- **Python 3.14 wheels**: scipy/pandas may lag on brand-new Python. Fix is in
  the script output — create a 3.12 venv (`py -3.12 -m venv .venv`) and rerun
  inside it.
- **Scapy needs no Npcap** for our use: generators only *write* PCAP files;
  replay happens in the VM via tcpreplay.

Smoke-test the LLM triage offline:
```powershell
python -c "from triage.llm import narrate; from alerts.schema import Alert, ThreatClass; from datetime import datetime, timezone; a=Alert(timestamp=datetime.now(timezone.utc), flow_id='h1', threat_class=ThreatClass.BEACONING, confidence_score=0.9, supporting_evidence=[{'feature':'iat_cv','value':0.1,'threshold':0.35}]); print(narrate(a))"
```

Expect status `ready` with `[EV:0]` citations, or `template` if Ollama isn't
running — both are acceptable behavior; never an exception.

---

## 3. Ubuntu VM Setup

### 3.1 Create the VM
1. Install VirtualBox. New VM: **Ubuntu 22.04 LTS**, 2 vCPU, 4 GB RAM, 30 GB disk.
2. Settings → Network → Adapter 1 → **Bridged Adapter** (needed for host↔VM
   iperf3 throughput runs and for a future two-machine demo).
3. Install Ubuntu, then inside it:

```bash
sudo apt update && sudo apt install -y virtualbox-guest-utils python3-pip
```

### 3.2 Provision
Copy the project folder into the VM (shared folder or `git clone`), then:
```bash
sudo ./setup_ubuntu.sh
python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
```

### 3.3 Zeek Install Fallbacks
- Try `apt install zeek` first.
- If absent on your release: OBS repo lines are printed by the script.
- Last resort: Docker — `docker pull zeek/zeek-lts` and run with
  `--net=host -v $(pwd):/workdir` capturing a host interface.

### 3.4 Why Not WSL2?
tcpreplay raw-socket injection and reliable passive capture are unreliable
under WSL2 NAT. Fine for editing code; do not depend on it for capture paths.

---

## 4. Lab Topology (Single VM)

```
        attacker namespace                target namespace
      ┌──────────────────┐            ┌──────────────────────┐
      │ hping3 / nmap /  │   veth     │ Zeek -i veth-t       │
      │ tcpreplay /      │ ══════════ │ (passive monitor)    │
      │ scapy replays    │  pair      │ iperf3 -s (target)   │
      │ 10.200.0.1       │            │ 10.200.0.2           │
      └──────────────────┘            └──────────────────────┘
```

Bring it up:
```bash
sudo bash benchmarks/topology_veth.sh up
# Terminal 1:  ip netns exec tgt zeek -i veth-t local
# Terminal 2:  ip netns exec att tcpreplay-edit --intf1=veth-a --topspeed datasets/beaconing.pcap
```

Two-laptop variant (later, for honest Mbps claims): laptop B boots Ubuntu,
laptop A generates/replays toward it over a direct Ethernet cable, laptop B's
Zeek monitors its physical interface. Same commands minus namespaces.

---

## 5. Phase A Acceptance Checks — Do These BEFORE Writing Detectors

1. `setup_windows.ps1` completes; schema smoke test prints a severity number.
2. VM up; `topology_veth.sh up`; ping att→tgt (`ip netns exec att ping 10.200.0.2`).
3. Generate one PCAP on Windows, copy into VM, replay at topspeed into the veth.
4. Zeek writes conn.log/dns.log rows matching the generated traffic.
5. Dashboard: `uvicorn dashboard.main:app --port 8080`, POST a test alert via
   `curl -X POST localhost:8080/alerts -H 'Content-Type: application/json' -d @sample_alert.json`,
   see it appear live in the browser over WebSocket.
6. Triage smoke test returns `ready` or `template`.

All six green = pipeline skeleton complete; detector work can start.

---

## 6. Phased Build Plan

| Phase | When | Work | Done When |
|---|---|---|---|
| A Environment | week before / H0–H2 | Section 5 checklist | all six checks green |
| B Generators | parallel from H0 | all class PCAPs + benign mix | labeled `datasets/` per class |
| C Detectors | H4–H20 | c → e → b → a → f → d | each passes vs its own PCAP |
| D Assembly | H16–H26 | dedup + hash chain, async triage, dashboard polish | end-to-end replay shows alerts + briefings |
| E Benchmarks | H26–H32 | throughput ladder, latency p50/p95, P/R/F1 tables | docs/validation.md filled |
| F Rehearsal | H32–H36 | demo narrative, slides, backup recordings | 10-min demo run clean twice |

Demo narrative arc: benign traffic flowing → dnscat-style tunnel starts →
alert fires within seconds → dashboard severity/confidence → briefing cites
evidence ids → throughput slide with measured numbers.

---

## 7. Benchmark Methodology

- **Throughput ladder:** merge benign + attack into `mixed_eval.pcap`;
  `tcpreplay-edit --mbps=10/25/50/100/...` rungs upward. At each rung record:
  intended Mbps, achieved Mbps, Zeek drop rate (`stats.log`), alert correctness.
  The sustained number = highest rung with acceptable drop rate + SLA.
- **Latency:** each evaluation alert carries packet timestamp (from pcap) and
  emission timestamp (dashboard receipt); `benchmarks/latency_measure.py`
  reports p50/p95 against the ≤5 s planning SLA.
- **Per-class P/R/F1:** labeled replay runs; ground truth = generator filename;
  results land in `docs/validation.md`. Report measured values only.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `pip install scipy` fails on Python 3.14 | use a 3.12 venv (section 2) |
| `zeek: command not found` after apt attempt | OBS repo or Docker fallback |
| tcpreplay sends but Zeek sees nothing | wrong namespace/interface — recheck section 4 exact commands |
| Ollama connection refused | service not running: `ollama serve` in background |
| Dashboard empty | POST an alert manually (section 5 check 5) to isolate WS vs pipeline |
| goflow2 download 404 | grab current release binary from github.com/netsampler/goflow2/releases |

---

## 9. Deliverables Checklist

- [ ] Working prototype, source repository (this repo)
- [ ] Documentation of models used → `docs/models.md`
- [ ] Features engineered → `docs/features.md`
- [ ] Training/validation approach → `docs/validation.md`
- [ ] Dashboard with live/replayed detections showing **severity and confidence**
- [ ] Constraints (a)–(e): read-only ingest · no decryption · streaming bounded latency · demonstrated throughput · standardized schema