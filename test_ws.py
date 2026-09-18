from fastapi.testclient import TestClient
from dashboard.main import app, alerts_store
import urllib.parse

client = TestClient(app)

# Ingest an alert
response = client.post('/alerts', json={
    'timestamp': '2026-09-17T19:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
})
print('Ingest:', response.json())

key = list(alerts_store.keys())[0]
print('Key:', key)

# Test WebSocket connection
with client.websocket_connect('/ws') as ws:
    # Receive initial alerts
    msg = ws.receive_json()
    print('Initial WS message count:', len(msg))
    
    # Update the alert via PATCH
    import urllib.parse
    response = client.patch(f'/alerts/{urllib.parse.quote(key, safe="")}', json={'briefing_status': 'ready', 'briefing_text': 'WS test briefing'})
    print('PATCH:', response.status_code)
    
    # Receive the update via WebSocket
    try:
        msg = ws.receive_json()
        print('WS update received:', msg.get('briefing_status'), msg.get('briefing_text')[:40])
    except Exception as e:
        print('WS error:', e)

print('WebSocket test complete!')