"""Air-gapped LLM triage — narrative assembly only (PLAN §4 Stage 4).

Contract:
- Input is the alert JSON; the LLM never sees raw payloads (there are none).
- Every factual claim must cite an evidence id as [EV:n]; the validator strips
  uncited sentences before display.
- Severity/confidence are narrated from input values, never invented.
- On failure/timeout -> templates.template_briefing(), briefing_status="template".

Runs against a local Ollama instance only (no cloud, no exceptions).
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from alerts.schema import Alert
from triage.templates import template_briefing

OLLAMA_URL = "http://localhost:11434/api/chat"
MODEL = "llama3.2:3b"
TIMEOUT_S = 30

SYSTEM_PROMPT = (
    "You are a SOC triage assistant. You receive one security alert as JSON. "
    "Write a 3-6 sentence briefing for an analyst. HARD RULES: "
    "(1) Every factual claim MUST cite its evidence id in square brackets "
    "like [EV:0]. Sentences without a citation are removed automatically. "
    "(2) Never invent features, hosts, IPs, or numbers not present in the JSON. "
    "(3) Report severity and confidence exactly as given. "
    "(4) End with one recommended human action."
)

_CITE_RE = re.compile(r"\[EV:\d+\]")


@dataclass
class Briefing:
    text: str
    status: str  # "ready" | "template"


def _strip_uncited(text: str) -> str:
    kept = [s.strip() for s in re.split(r"(?<=[.!?])\s+", text) if s and _CITE_RE.search(s)]
    return " ".join(kept)


def build_prompt(alert: Alert) -> str:
    payload = {
        "timestamp": alert.timestamp.isoformat(),
        "flow_id": alert.flow_id,
        "threat_class": alert.threat_class.value,
        "confidence_score": alert.confidence_score,
        "severity": alert.severity,
        "evidence": [e.model_dump() for e in alert.supporting_evidence],
    }
    return json.dumps(payload, indent=2)


def narrate(alert: Alert) -> Briefing:
    body = {
        "model": MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(alert)},
        ],
        "stream": False,
        "options": {"temperature": 0},
    }
    try:
        req = urllib.request.Request(
            OLLAMA_URL, data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            content = json.loads(resp.read())["message"]["content"]
    except (urllib.error.URLError, TimeoutError, KeyError, json.JSONDecodeError):
        return Briefing(text=template_briefing(alert), status="template")

    cleaned = _strip_uncited(content)
    if not cleaned:
        return Briefing(text=template_briefing(alert), status="template")
    return Briefing(text=cleaned, status="ready")
