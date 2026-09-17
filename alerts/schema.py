"""Alert schema — implements the specification in PLAN.md Section 4.

Severity and confidence are computed deterministically in the detection layer,
never by the LLM. Severity = floor(base * confidence + 0.5), clipped to [1, 5]
(floor(x+0.5) instead of round() to avoid Python banker's rounding).
"""

from __future__ import annotations

import hashlib
import json
import math
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class ThreatClass(str, Enum):
    SYN_FLOOD = "syn_flood"
    UDP_FLOOD = "udp_flood"
    SLOWLORIS = "slowloris"
    BEACONING = "beaconing"
    DGA_DOMAIN = "dga_domain"
    DNS_TUNNELING = "dns_tunneling"
    ENCRYPTED_MALWARE = "encrypted_malware"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"


BASE_SEVERITY: dict[ThreatClass, int] = {
    ThreatClass.DATA_EXFILTRATION: 5,
    ThreatClass.ENCRYPTED_MALWARE: 4,
    ThreatClass.BEACONING: 4,
    ThreatClass.SYN_FLOOD: 3,
    ThreatClass.UDP_FLOOD: 3,
    ThreatClass.SLOWLORIS: 3,
    ThreatClass.DNS_TUNNELING: 3,
    ThreatClass.DGA_DOMAIN: 3,
    ThreatClass.PORT_SCAN: 2,
}

BriefingStatus = Literal["pending", "ready", "template"]


class Evidence(BaseModel):
    feature: str
    value: Any
    threshold: Optional[float] = None
    matched_list: Optional[str] = None


class Alert(BaseModel):
    timestamp: datetime
    flow_id: str
    threat_class: ThreatClass
    confidence_score: float = Field(ge=0.0, le=1.0)
    severity: Optional[int] = Field(default=None, ge=1, le=5)
    briefing_status: BriefingStatus = "pending"
    supporting_evidence: list[Evidence] = Field(min_length=1)
    prev_hash: str = ""
    self_hash: str = ""

    @field_validator("timestamp")
    @classmethod
    def _utc(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @model_validator(mode="after")
    def _compute_severity(self) -> "Alert":
        if self.severity is None:
            base = BASE_SEVERITY[self.threat_class]
            self.severity = min(5, max(1, math.floor(base * self.confidence_score + 0.5)))
        return self


def evidence_canonical_json(alert: Alert) -> str:
    payload = [e.model_dump(mode="json") for e in alert.supporting_evidence]
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_self_hash(alert: Alert) -> str:
    """Hash of this alert's evidence plus the previous record's hash."""
    material = f"{alert.prev_hash}|{evidence_canonical_json(alert)}"
    return hashlib.sha256(material.encode()).hexdigest()


def chain(alerts: list[Alert]) -> list[Alert]:
    """Assign the append-only hash chain across an ordered alert list."""
    out: list[Alert] = []
    prev = ""
    for a in sorted(alerts, key=lambda x: x.timestamp):
        a.prev_hash = prev
        a.self_hash = compute_self_hash(a)
        prev = a.self_hash
        out.append(a)
    return out