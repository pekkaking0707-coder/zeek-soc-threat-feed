"""Deterministic fallback briefing — zero LLM involvement (PLAN §5 lifecycle).

Used when the local model fails, times out, or returns text that fails the
citation validator. The pipeline degrades to this, never to silence.
"""

from __future__ import annotations

from alerts.schema import Alert

ACTION_HINTS = {
    "syn_flood": "Verify upstream scrubbing; confirm whether the source range is legitimate.",
    "udp_flood": "Check amplification-vector exposure (DNS/NTP/Memcached) on the targeted service.",
    "slowloris": "Inspect web-server worker pool exhaustion; consider raising connection limits at the proxy.",
    "beaconing": "Isolate the internal host and capture volatile memory for IR before reboot.",
    "dga_domain": "Sinkhole the domain; audit the resolving host for the implant that generated it.",
    "dns_tunneling": "Block the authoritative DNS path and inspect the querying host for tunnelling tools.",
    "encrypted_malware": "Match the fingerprint fleet-wide; isolate the endpoint pending forensic review.",
    "port_scan": "Correlate with perimeter telemetry; confirm exposure of the probed ports.",
    "data_exfiltration": "Freeze the account/host; quantify scope of data moved before containment.",
}


def template_briefing(alert: Alert) -> str:
    lines = [
        f"[TEMPLATE BRIEFING] {alert.threat_class.value} alert on {alert.flow_id}.",
        f"Severity {alert.severity}/5, confidence {alert.confidence_score:.2f}.",
    ]
    for i, ev in enumerate(alert.supporting_evidence):
        bits = [f"EV:{i}", ev.feature, f"= {ev.value}"]
        if ev.threshold is not None:
            bits.append(f"(threshold {ev.threshold})")
        if ev.matched_list:
            bits.append(f"[{ev.matched_list}]")
        lines.append("Evidence " + " ".join(str(b) for b in bits) + ".")
    lines.append(
        "Recommended action: "
        + ACTION_HINTS.get(alert.threat_class.value,
                           "Route to on-call analyst for manual review.")
    )
    return " ".join(lines)
