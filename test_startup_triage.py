import asyncio
from fastapi.testclient import TestClient
from dashboard.main import app, alerts_store

client = TestClient(app)

# Add a pending alert
response = client.post('/alerts', json={
    'timestamp': '2026-09-17T21:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
})
print('Ingest:', response.json())

# Check initial state
from dashboard.main import alerts_store
key = list(alerts_store.keys())[0]
print('Initial status:', alerts_store[key]['briefing_status'])

# The TestClient doesn't run startup events, so we need to manually trigger the background task
# But we can test that the endpoint works
import asyncio
from triage.llm import narrate
from alerts.schema import Alert, ThreatClass
from datetime import datetime, timezone

async def test():
    from dashboard.main import alerts_store, _update_alert_in_store
    from triage.llm import narrate
    from alerts.schema import Alert, ThreatClass
    from datetime import datetime, timezone

    key = list(alerts_store.keys())[0]
    print('Initial status:', alerts_store[key]['briefing_status'])

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

    # Update via the store
    from dashboard.main import _update_alert_in_store, alerts_store
    _update_alert_in_store(key, {'briefing_status': briefing.status, 'briefing_text': briefing.text})
    print('Updated status:', alerts_store[key]['briefing_status'])

asyncio.run(test())