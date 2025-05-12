import json
from scapy.all import sniff, IP
import firebase_admin
from firebase_admin import credentials, firestore

# Load configuration from config.json
try:
    with open('config.json', 'r') as config_file:
        config = json.load(config_file)
except Exception as e:
    print(f"Failed to load config.json: {e}")
    exit(1)

firebase_credential_path = config['firebase_credential_path']
network_interface = config.get('network_interface')
capture_method = config['capture_method']
capture_file_path = config.get('capture_file_path')

# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credential_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

def run_ids_capture(packet_queue, stop_event):
    # Fetch the malicious IP addresses from Firestore
    malicious_ips_ref = db.collection(u'malicious_ips')
    malicious_ips_docs = malicious_ips_ref.stream()
    malicious_ips = set(doc.to_dict().get('ip', '').strip() for doc in malicious_ips_docs)

    print(f"Fetched malicious IPs: {malicious_ips}")

    def packet_callback(packet):
        if IP in packet:
            src_ip = packet[IP].src.strip()
            dst_ip = packet[IP].dst.strip()
            print(f"Checking packet: Source: {src_ip}, Destination: {dst_ip}")  # Log packet details
            
            # Check if source or destination IP is in the set of malicious IPs
            if src_ip in malicious_ips or dst_ip in malicious_ips:
                print(f"ALERT: Malicious IP detected - Source: {src_ip}, Destination: {dst_ip}")
                packet_queue.put({'type': 'alert', 'data': {'src_ip': src_ip, 'dst_ip': dst_ip, 'threat': {'severity': 'High'}}})
            else:
                print(f"Source: {src_ip}, Destination: {dst_ip} - No match found")
                packet_queue.put({'type': 'log', 'data': {'Number of Packet': 1, 'dst_ip': dst_ip, 'src_ip': src_ip, 'payload': '', 'protocol': packet[IP].proto, 'timestamp': packet.time}})
            
            # Here you can add logic to check against Snort rules if necessary

    sniff(iface="Wi-Fi", prn=packet_callback, store=0, stop_filter=lambda x: stop_event.is_set())
