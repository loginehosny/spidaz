import firebase_admin
from firebase_admin import credentials, firestore

# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate("E:/gp/serviceAccountKey.json")
    firebase_admin.initialize_app(cred)
db = firestore.client()


new_rule = {
    'action': 'alert',
    'protocol': 'icmp',
    'source': 'any',
    'source_port': 'any',
    'destination': '8.8.8.8',
    'destination_port': 'any',
    'options': 'msg:"ICMP Ping to malicious IP 8.8.8.8"; sid:1000001;'
}

new_rule = {
    'action': 'alert',
    'protocol': 'tcp',
    'source': 'any',
    'source_port': 'any',
    'destination': '192.168.1.100',
    'destination_port': '80',
    'options': 'msg:"HTTP traffic to specific IP"; sid:1000002;'
}

new_rule = {
    'action': 'alert',
    'protocol': 'TCP',
    'source': 'any',
    'source_port': 'any',
    'destination': '35.174.127.31',
    'destination_port': '80',
    'options': 'msg:"HTTP traffic to specific IP"; sid:1000003;'
}

new_rule = {
    'action': 'alert',
    'protocol': 'icmp',
    'source': 'any',
    'source_port': 'any',
    'destination': '127.0.0.1',
    'destination_port': 'any',
    'options': 'msg:"ICMP Ping to malicious IP "; sid:1000005;'
}
new_rule = {
        'action': 'alert',
        'protocol': 'tcp',
        'source': 'any',
        'source_port': 'any',
        'destination': '142.250.201.46',
        'destination_port': '80',
        'options': 'sid:1000002; rev:1;',
        'severity': 'high'
    }
   
new_rule = {
  "action": "alert",
  "protocol": "any",
  "source": "any",
  "source_port": "any",
  "destination": "142.250.201.46",
  "destination_port": "any",
  "options": "sid:1000003; rev:1;",
  "severity": "high"
}

new_rule = {
  "action": "alert",
  "protocol": "any",
  "source": "172.20.10.2",
  "source_port": "any",
  "destination": "142.250.201.46",
  "destination_port": "any",
  "options": "sid:1000003; rev:1;",
  "severity": "high"
}




db.collection('snort_rules').add(new_rule)
print("New rule added to Firebase.")
