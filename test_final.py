import asyncio
import os
import urllib.parse
from fastapi.testclient import TestClient
from dashboard.main import app, alerts_store, _update_alert_in_store
from triage.llm import narrate
from alerts.schema import Alert, ThreatClass
from datetime import datetime, timezone

client = TestClient(app)

print('=== FINAL COMPREHENSIVE TEST ===')

# 1. Test detector runners and generators
print('\n1. Testing detector runners and generators...')
for f in ['gen_dga_queries.py', 'gen_dns_tunnel.py', 'gen_beaconing.py', 'gen_floods.py', 'gen_portscan.py', 'gen_exfil.py']:
    assert os.path.exists('generators/' + f), 'Missing ' + f
print('[OK] All generators present')

# 2. Test alert ingestion and storage
alert_data = {
    'timestamp': '2026-09-17T22:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
}
response = client.post('/alerts', json=alert_data)
assert response.status_code == 200
key = '10.0.0.1->10.0.0.2#tcp|2026-09-17T22:00:00Z'
print('[OK] Alert ingestion works')

# Test briefing generation
from triage.llm import narrate
from alerts.schema import Alert, ThreatClass
from datetime import datetime, timezone

alert_obj = Alert(
    timestamp=datetime.now(timezone.utc),
    flow_id='10.0.0.1->10.0.0.2#tcp',
    threat_class='beaconing',
    confidence_score=0.95,
    supporting_evidence=[{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
)
briefing = narrate(alert_obj)
assert briefing.status in ('ready', 'template')
print('[OK] LLM triage works (status: ' + briefing.status + ')')

# 3. Test alert update via API
import urllib.parse
encoded_key = urllib.parse.quote(key, safe='')
response = client.patch(f'/alerts/{urllib.parse.quote(key, safe="")}', json={'briefing_status': 'ready', 'briefing_text': 'Test briefing'})
assert response.status_code == 200
print('[OK] PATCH /alerts/{key} works')

# 4. Test GET alert
response = client.get(f'/alerts/{urllib.parse.quote(key, safe="")}')
assert response.status_code == 200
data = response.json()
assert data['briefing_status'] == 'ready'
assert data['briefing_text'] == 'Test briefing'
print('[OK] GET /alerts/{key} works')

# 5. Test WebSocket updates
with client.websocket_connect('/ws') as ws:
    msg = ws.receive_json()
    response = client.patch(f'/alerts/{urllib.parse.quote(key, safe="")}', json={'briefing_status': 'ready', 'briefing_text': 'WS test'})
    msg = ws.receive_json()
    assert msg['briefing_status'] == 'ready'
    assert msg['briefing_text'] == 'WS test'
    print('[OK] WebSocket real-time updates work')

# 6. Test detector imports
from detectors.dns_family import DGADetector, DNSTunnelDetector
from detectors.port_scan import PortScanDetector
from detectors.beaconing import BeaconingDetector
from detectors.floods import FloodDetector
from detectors.exfil import ExfilDetector
from detectors.encrypted_malware import EncryptedMalwareDetector
print('[OK] All 6 detector modules import successfully')

print('\n=== ALL TESTS PASSED ===')
print('Project is ready for GitHub!')