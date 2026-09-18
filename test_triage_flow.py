import asyncio
from datetime import datetime, timezone
from alerts.schema import Alert, ThreatClass
from triage.llm import narrate

# Test the triage flow
from dashboard.main import _add_alert, alerts_store, _update_alert_in_store
from alerts.schema import Alert, ThreatClass
from triage.llm import narrate

# Add a test alert
alert = {
    'timestamp': '2026-09-17T18:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'severity': 4,
    'briefing_status': 'pending',
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}],
    'prev_hash': '',
    'self_hash': ''
}
key = f"{alert['flow_id']}|{alert['timestamp']}"
alerts_store[key] = alert
print('Added alert, status:', alerts_store[key]['briefing_status'])

# Test LLM narration (will use template fallback since Ollama not running)
from triage.llm import narrate
from alerts.schema import Alert as AlertModel, ThreatClass
from datetime import datetime, timezone

alert_obj = Alert(
    timestamp=datetime.now(timezone.utc),
    flow_id='10.0.0.1->10.0.0.2#tcp',
    threat_class=ThreatClass.BEACONING,
    confidence_score=0.95,
    supporting_evidence=[{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
)

briefing = narrate(alert_obj)
print('Briefing status:', briefing.status)
print('Briefing text preview:', briefing.text[:100])

# Simulate the update
key = list(alerts_store.keys())[0]
from dashboard.main import _update_alert_in_store
_update_alert_in_store(key, {'briefing_status': briefing.status, 'briefing_text': briefing.text})
print('Updated briefing_status:', alerts_store[key]['briefing_status'])
print('Briefing text:', alerts_store[key]['briefing_text'][:80])