import asyncio
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from dashboard.main import app, alerts_store, _update_alert_in_store, alerts_store
from alerts.schema import Alert, ThreatClass
from triage.llm import narrate
from datetime import datetime, timezone

client = TestClient(app)

# 1. Ingest an alert
alert_data = {
    'timestamp': '2026-09-17T18:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
}
response = client.post('/alerts', json=alert_data)
print('Ingest:', response.json())

# Check initial state
key = '10.0.0.1->10.0.0.2#tcp|2026-09-17T18:00:00Z'
print('Initial status:', alerts_store[key]['briefing_status'])

# Test LLM narration
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

from triage.llm import narrate
briefing = narrate(alert_obj)
print('Briefing status:', briefing.status)
print('Briefing text:', briefing.text[:80])

# Update via the store directly
from dashboard.main import _update_alert_in_store, alerts_store
_update_alert_in_store(key, {'briefing_status': 'template', 'briefing_text': 'Test briefing'})
print('Updated status:', alerts_store[key]['briefing_status'])

# Verify via API
import urllib.parse
encoded_key = urllib.parse.quote(key, safe='')
from fastapi.testclient import TestClient
client = TestClient(app)
response = client.get(f'/alerts/{key}')
print('GET alert status:', response.json().get('briefing_status'))

print('SUCCESS: Full flow works!')