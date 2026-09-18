from fastapi.testclient import TestClient
from dashboard.main import app, alerts_store
import urllib.parse

client = TestClient(app)

# Ingest an alert
response = client.post('/alerts', json={
    'timestamp': '2026-09-17T18:00:00Z',
    'flow_id': '10.0.0.1->10.0.0.2#tcp',
    'threat_class': 'beaconing',
    'confidence_score': 0.95,
    'supporting_evidence': [{'feature': 'iat_cv', 'value': 0.05, 'threshold': 0.35}]
})
print('Ingest:', response.json())

# Get the key
key = list(alerts_store.keys())[0]
print('Key:', repr(key))

# Update via PATCH (with URL encoding)
encoded_key = urllib.parse.quote(key, safe='')
print('Encoded key:', encoded_key)

response = client.patch(f'/alerts/{urllib.parse.quote(key, safe="")}', json={'briefing_status': 'ready', 'briefing_text': 'Test briefing'})
print('PATCH response:', response.status_code, response.json())

# Now GET with proper encoding
response = client.get(f'/alerts/{urllib.parse.quote(key, safe="")}')
print('GET status:', response.status_code)
print('GET response:', response.json())