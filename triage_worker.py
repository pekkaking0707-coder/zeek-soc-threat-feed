#!/usr/bin/env python3
"""
Standalone LLM Triage Worker

This script can be run as a standalone worker to process pending alerts
via the FastAPI REST API. Useful when running the LLM on a separate machine
or when the background task in the FastAPI app is not used.

Usage:
    python triage_worker.py --api-url http://localhost:8080 --interval 5
"""

import argparse
import asyncio
import json
import sys
import time
import urllib.request
import urllib.error

from alerts.schema import Alert


def get_pending_alerts(api_url: str) -> list[dict]:
    """Fetch all alerts with briefing_status=pending."""
    try:
        req = urllib.request.Request(f"{api_url}/alerts")
        with urllib.request.urlopen(req, timeout=10) as resp:
            alerts = json.loads(resp.read())
            return [a for a in alerts if a.get("briefing_status") == "pending"]
    except Exception as e:
        print(f"Error fetching alerts: {e}", file=sys.stderr)
        return []


def get_alert(api_url: str, key: str) -> dict | None:
    """Fetch a single alert by key."""
    try:
        # URL-encode the key
        import urllib.parse
        encoded_key = urllib.parse.quote(key, safe="")
        req = urllib.request.Request(f"http://localhost:8000/alerts/{key}")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        print(f"Error fetching alert {key}: {e}", file=sys.stderr)
        return None


def update_alert_briefing(api_url: str, key: str, briefing_text: str, status: str) -> bool:
    """Update an alert's briefing via the API."""
    import urllib.parse
    encoded_key = urllib.parse.quote(key, safe="")
    url = f"http://localhost:8000/alerts/{key}"
    data = json.dumps({"briefing_status": status, "briefing_text": briefing_text}).encode()
    try:
        req = urllib.request.Request(
            f"http://localhost:8000/alerts/{urllib.parse.quote(key, safe='')}",
            data=json.dumps({"briefing_status": status, "briefing_text": briefing_text}).encode(),
            headers={"Content-Type": "application/json"},
            method="PATCH"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"Error updating alert {key}: {e}", file=sys.stderr)
        return False


def build_prompt(alert: dict) -> str:
    import json
    payload = {
        "timestamp": alert["timestamp"],
        "flow_id": alert["flow_id"],
        "threat_class": alert["threat_class"],
        "confidence_score": alert["confidence_score"],
        "severity": alert["severity"],
        "evidence": alert["supporting_evidence"],
    }
    return json.dumps(payload, indent=2)


def call_ollama(prompt: str, model: str = "llama3.2:3b", url: str = "http://localhost:11434/api/chat") -> str | None:
    """Call Ollama API for chat completion."""
    body = {
        "model": "llama3.2:3b",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "options": {"temperature": 0},
    }
    try:
        req = urllib.request.Request(
            "http://localhost:11434/api/chat",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read())["message"]["content"]
    except Exception as e:
        print(f"Ollama error: {e}", file=sys.stderr)
        return None


SYSTEM_PROMPT = (
    "You are a SOC triage assistant. You receive one security alert as JSON. "
    "Write a 3-6 sentence briefing for an analyst. HARD RULES: "
    "(1) Every factual claim MUST cite its evidence id in square brackets "
    "like [EV:0]. Sentences without a citation are removed automatically. "
    "(2) Never invent features, hosts, IPs, or numbers not present in the JSON. "
    "(3) Report severity and confidence exactly as given. "
    "(4) End with one recommended human action."
)

_CITE_RE = __import__("re").compile(r"\[EV:\d+\]")


def _strip_uncited(text: str) -> str:
    kept = [s.strip() for s in __import__("re").split(r"(?<=[.!?])\s+", text) if s and _CITE_RE.search(s)]
    return " ".join(kept)


def process_alert(alert: dict) -> tuple[str, str]:
    """Process a single alert through the LLM. Returns (status, briefing_text)."""
    # Build prompt
    prompt = build_prompt(alert)

    # Call Ollama
    content = call_ollama(prompt)
    if content is None:
        # Fallback to template
        from triage.templates import template_briefing
        from alerts.schema import Alert as AlertModel
        alert_obj = __import__("alerts.schema", fromlist=["Alert"]).Alert.model_validate(alert)
        from triage.templates import template_briefing
        return "template", template_briefing(alert_obj)

    # Strip uncited sentences
    cleaned = _strip_uncited(content)
    if not cleaned:
        from triage.templates import template_briefing
        from alerts.schema import Alert as AlertModel
        alert_obj = __import__("alerts.schema", fromlist=["Alert"]).Alert.model_validate(alert)
        return "template", template_briefing(alert_obj)

    return "ready", cleaned


async def process_pending_alerts(api_url: str = "http://localhost:8000"):
    """Process all pending alerts."""
    pending = get_pending_alerts(api_url)
    if not pending:
        return 0

    print(f"Found {len(pending)} pending alerts")
    processed = 0

    for alert in pending:
        key = f"{alert['flow_id']}|{alert['timestamp']}"
        print(f"Processing {key}...")

        status, briefing = process_alert(alert)

        # Update via API
        import urllib.parse
        encoded_key = __import__("urllib.parse").quote(key, safe="")
        url = f"http://localhost:8000/alerts/{key}"
        data = {"briefing_status": status, "briefing_text": alert.get("briefing_text", "")}
        # Use direct store update since we're on the same machine
        import sys
        sys.path.insert(0, ".")
        from dashboard.main import alerts_store, _update_alert_in_store
        _update_alert_in_store(key, {"briefing_status": status, "briefing_text": alert.get("briefing_text", "")})
        # Update the briefing text
        from dashboard.main import alerts_store as store
        store[key]["briefing_text"] = "Updated by worker"

        print(f"  Updated {key}: {status}")
        processed += 1

    return processed


async def main():
    parser = argparse.ArgumentParser(description="LLM Triage Worker")
    parser.add_argument("--api-url", default="http://localhost:8000", help="FastAPI base URL")
    parser.add_argument("--interval", type=int, default=5, help="Polling interval (seconds)")
    parser.add_argument("--once", action="store_true", help="Run once and exit")
    args = parser.parse_args()

    print(f"Starting triage worker (interval={args.interval}s)")

    if args.once:
        await process_pending_alerts(args.api_url)
    else:
        while True:
            try:
                await process_pending_alerts(args.api_url)
            except Exception as e:
                print(f"Worker error: {e}")
            await asyncio.sleep(args.interval)


if __name__ == "__main__":
    asyncio.run(main())