"""SOC Dashboard — FastAPI + WebSocket live view.

Run:  uvicorn dashboard.main:app --reload --port 8080
Open: http://localhost:8080/

Pipeline pushes alerts via POST /alerts; browsers receive them over /ws.
The LLM briefing attaches asynchronously: briefing_status moves
pending -> ready|template without gating delivery (constraint c).
"""

from __future__ import annotations

import asyncio
from collections import deque
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from alerts.schema import Alert

app = FastAPI(title="Zeek SOC Threat Feed Dashboard")
recent: deque[dict] = deque(maxlen=500)
clients: set[WebSocket] = set()

INDEX = Path(__file__).parent / "static" / "index.html"


@app.post("/alerts")
async def ingest(alert: Alert) -> dict:
    item = alert.model_dump(mode="json")
    recent.appendleft(item)
    await asyncio.gather(*(c.send_json(item) for c in list(clients)),
                         return_exceptions=True)
    return {"queued": True}


@app.websocket("/ws")
async def stream(ws: WebSocket) -> None:
    await ws.accept()
    clients.add(ws)
    try:
        for item in list(recent):
            await ws.send_json(item)
        while True:
            await ws.receive_text()  # keepalive pings from browser
    except WebSocketDisconnect:
        clients.discard(ws)


@app.get("/")
async def index():
    return FileResponse(INDEX)