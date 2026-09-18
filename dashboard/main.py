"""SOC Dashboard — FastAPI + WebSocket live view.

Run:  uvicorn dashboard.main:app --reload --port 8080
Open: http://localhost:8080/

Pipeline pushes alerts via POST /alerts; browsers receive them over /ws.
The LLM briefing attaches asynchronously: briefing_status moves
pending -> ready|template without gating delivery.
"""

from __future__ import annotations

import asyncio
import json
from collections import deque
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import FileResponse

from alerts.schema import Alert

app = FastAPI(title="Zeek SOC Threat Feed Dashboard")

# In-memory alert store with O(1) lookup by flow_id + timestamp key
alerts_store: dict[str, dict] = {}  # key: "flow_id|timestamp" -> alert dict
recent: list[dict] = []  # Ordered list for recent view (newest first)
MAX_RECENT = 500

clients: set = set()

INDEX = Path(__file__).parent / "static" / "index.html"


def _make_key(alert: dict) -> str:
    """Create a unique key for an alert."""
    return f"{alert['flow_id']}|{alert['timestamp']}"


def _update_alert_in_store(key: str, updates: dict) -> bool:
    """Update an alert in the store and recent list."""
    if key not in alerts_store:
        return False
    alerts_store[key].update(updates)
    # Also update in recent list
    for i, alert in enumerate(recent):
        if _make_key(alert) == key:
            recent[i].update(updates)
            break
    return True


def _add_alert(alert: dict) -> str:
    """Add alert to store and recent list. Returns the key."""
    key = _make_key(alert)
    alerts_store[key] = alert
    recent.insert(0, alert)
    if len(recent) > 500:
        # Remove oldest from both
        old = recent.pop()
        old_key = _make_key(old)
        alerts_store.pop(old_key, None)
    return key


@app.post("/alerts")
async def ingest(alert: dict) -> dict:
    """Ingest an alert from detectors."""
    # Validate using Pydantic
    from alerts.schema import Alert as AlertModel
    try:
        alert_obj = Alert.model_validate(alert)
        item = alert_obj.model_dump(mode="json")
    except Exception as e:
        raise HTTPException(status_code=422, detail=str(e))

    key = _add_alert(item)
    # Broadcast to WebSocket clients
    import asyncio
    await asyncio.gather(*(c.send_json(item) for c in list(clients)),
                         return_exceptions=True)
    return {"queued": True, "key": key}


@app.patch("/alerts/{key}")
async def update_alert(key: str, updates: dict) -> dict:
    """Update an alert (used by triage worker to attach briefing)."""
    allowed_fields = {"briefing_status", "briefing_text"}
    updates = {k: v for k, v in updates.items() if k in allowed_fields}
    if not updates:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    if not _update_alert_in_store(key, updates):
        raise HTTPException(status_code=404, detail="Alert not found")

    # Broadcast updated alert to WebSocket clients
    updated = alerts_store[key]
    import asyncio
    await asyncio.gather(*(c.send_json(updated) for c in list(clients)),
                         return_exceptions=True)
    return {"updated": True, "key": key}


@app.get("/alerts")
async def list_alerts(limit: int = 100) -> list[dict]:
    """List recent alerts."""
    return recent[:limit]


@app.get("/alerts/{key}")
async def get_alert(key: str) -> dict:
    """Get a specific alert by key."""
    if key not in alerts_store:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alerts_store[key]


@app.websocket("/ws")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    clients.add(ws)
    try:
        for item in list(recent):
            await ws.send_json(item)
        while True:
            await ws.receive_text()  # keepalive pings from browser
    except Exception:
        pass
    finally:
        clients.discard(ws)


@app.get("/")
async def index():
    return FileResponse(INDEX)


# Background task for LLM triage
async def triage_worker():
    """Background task that processes pending alerts through LLM."""
    from triage.llm import narrate
    from alerts.schema import Alert as AlertModel

    while True:
        try:
            # Find pending alerts
            for key, alert in list(alerts_store.items()):
                if alert.get("briefing_status") == "pending":
                    try:
                        # Convert to Alert model for LLM
                        alert_obj = AlertModel.model_validate(alert)
                        # Run LLM in thread pool to avoid blocking
                        import asyncio
                        loop = asyncio.get_event_loop()
                        briefing = await loop.run_in_executor(
                            None, lambda: narrate(alert_obj)
                        )
                        # Update alert with briefing
                        updates = {
                            "briefing_status": briefing.status,
                            "briefing_text": briefing.text,
                        }
                        _update_alert_in_store(key, updates)
                        # Broadcast update
                        updated = alerts_store[key]
                        import asyncio
                        await asyncio.gather(*(
                            c.send_json(updated) for c in list(clients)
                        ), return_exceptions=True)
                    except Exception as e:
                        print(f"Triage error for {key}: {e}")
                        # Mark as template on error
                        _update_alert_in_store(key, {
                            "briefing_status": "template",
                            "briefing_text": f"Error generating briefing: {e}"
                        })
        except Exception as e:
            print(f"Triage worker error: {e}")
        await asyncio.sleep(2)  # Poll every 2 seconds


@app.on_event("startup")
async def startup_event():
    """Start background tasks on startup."""
    asyncio.create_task(triage_worker())


@app.get("/health")
async def health():
    return {"status": "ok", "alerts": len(alerts_store)}