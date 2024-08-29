import pandas as pd
import random
from datetime import datetime, timedelta

def generate_mock_siem_data(num_records=100):
    data = []
    for _ in range(num_records):
        timestamp = datetime.now() - timedelta(days=random.randint(0, 30))
        data.append({
            'timestamp': timestamp.isoformat(),
            'source_ip': f'192.168.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'destination_ip': f'10.0.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'event_type': random.choice(['login_attempt', 'file_access', 'network_scan']),
            'severity': random.choice(['low', 'medium', 'high']),
            'description': f'Mock SIEM event {_}'
        })
    return pd.DataFrame(data)

def generate_mock_threat_intel(num_records=50):
    data = []
    for _ in range(num_records):
        data.append({
            'ip': f'10.0.{random.randint(1, 255)}.{random.randint(1, 255)}',
            'threat_type': random.choice(['malware', 'phishing', 'ransomware']),
            'confidence_score': random.uniform(0.5, 1.0),
            'last_seen': (datetime.now() - timedelta(days=random.randint(1, 30))).isoformat(),
            'description': f'Mock threat intel record {_}'
        })
    return pd.DataFrame(data)

# Save mock data to CSV files
siem_data = generate_mock_siem_data()
threat_intel = generate_mock_threat_intel()

siem_data.to_csv('mock_siem_data.csv', index=False)
threat_intel.to_csv('mock_threat_intel.csv', index=False)

print("Mock data generated and saved to CSV files.")
