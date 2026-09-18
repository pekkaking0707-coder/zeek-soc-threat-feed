import asyncio
from dashboard.main import alerts_store, _update_alert_in_store
from triage.llm import narrate
from alerts.schema import Alert, ThreatClass
from datetime import datetime, timezone

async def test_triage():
    alerts_store.clear()
    alert = {
        'timestamp': '2026-09-17T20:00:00Z',
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
    print('Initial status:', alerts_store[key]['briefing_status'])

    # Simulate triage worker
    for key, alert in list(alerts_store.items()):
        if alert.get('briefing_status') == 'pending':
            print(f'Processing {key}...')
            alert_obj = Alert(
                timestamp=datetime.now(timezone.utc),
                flow_id=alert['flow_id'],
                threat_class=ThreatClass(alert['threat_class']),
                confidence_score=alert['confidence_score'],
                supporting_evidence=alert['supporting_evidence']
            )
            briefing = narrate(alert_obj)
            print(f'  Briefing status: {briefing.status}')
            _update_alert_in_store(key, {
                'briefing_status': briefing.status,
                'briefing_text': briefing.text
            })
            print(f'  Updated status: {alerts_store[key]["briefing_status"]}')

    print('Final status:', alerts_store[key]['briefing_status'])
    print('Briefing text:', alerts_store[key]['briefing_text'][:80])

asyncio.run(test_triage())