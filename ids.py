import json
import os
from scapy.all import sniff
import firebase_admin
from firebase_admin import credentials, firestore
import threading
import asyncio
from datetime import datetime
import pyshark
import queue
import re
from collections import deque
import joblib
from sklearn.neural_network import MLPClassifier
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer

# Load configuration from config.json
try:
    with open('Config.json', 'r') as config_file:
        config = json.load(config_file)
except Exception as e:
    print(f"Failed to load config.json: {e}")
    exit(1)

firebase_credential_path = config['firebase_credential_path']
network_interface = config.get('network_interface')
capture_methods = config['capture_method']
capture_file_path = config.get('capture_file_path')

# Initialize Firebase
if not firebase_admin._apps:
    cred = credentials.Certificate(firebase_credential_path)
    firebase_admin.initialize_app(cred)
db = firestore.client()

def fetch_malicious_ips():
    print("Fetching malicious IPs...")
    malicious_ips_ref = db.collection('malicious_ips')
    malicious_ips_docs = malicious_ips_ref.stream()
    malicious_ips = set(doc.to_dict().get('ip', '').strip() for doc in malicious_ips_docs)
    return malicious_ips

def fetch_snort_rules():
    print("Fetching snort rules...")
    rules_ref = db.collection('snort_rules')
    rules = rules_ref.stream()
    snort_rules = [rule.to_dict() for rule in rules]
    return snort_rules

def store_log(log_data):
    log_ref = db.collection('network_logs').document()
    log_ref.set(log_data)
    print(f"Stored log: {log_data}")

def trigger_alert(packet_queue, threat_info):
    print(f"Triggering alert: {threat_info}")
    packet_queue.put({'type': 'alert', 'data': threat_info})

def extract_options(options_str):
    options = {}
    # Extract content matches
    content_matches = re.findall(r'content:"([^"]+)"', options_str)
    if content_matches:
        options['content'] = content_matches
    
    # Extract PCRE matches
    pcre_matches = re.findall(r'pcre:"([^"]+)"', options_str)
    if pcre_matches:
        options['pcre'] = pcre_matches
    
    # Add more extraction logic for other options as needed
    return options

def match_options(options, packet_data):
    # Evaluate content matches
    if 'content' in options:
        for content_value in options['content']:
            if content_value.encode() not in packet_data:
                return False
    
    # Evaluate PCRE matches
    if 'pcre' in options:
        for pcre_pattern in options['pcre']:
            if not re.search(pcre_pattern, packet_data.decode(errors='ignore')):
                return False
    
    # Add more evaluations for other options as needed
    return True
    
# Initialize global variables to store total data and start time
total_data = 0
start_time = None
packet_window = deque(maxlen=100)


# Function to determine the state of the packet
def get_packet_state(packet):
    if 'TCP' in packet:
        tcp_flags = packet.tcp.flags
        return map_tcp_flags_to_state(tcp_flags)
    # Add more protocol checks if needed
    return "UNKNOWN"


# Function to map TCP flags to your specific states (CON and INT)
def map_tcp_flags_to_state(tcp_flags):
    flags = int(tcp_flags, 16)
    flag_fin = 0x01
    flag_syn = 0x02
    flag_rst = 0x04
    flag_psh = 0x08
    flag_ack = 0x10
    flag_urg = 0x20
    flag_ece = 0x40
    flag_cwr = 0x80

    # Mapping states based on TCP flags
    if flags & flag_syn and not flags & flag_ack:
        return "CON"  # Connection initiation (SYN flag set)
    elif flags & flag_syn and flags & flag_ack:
        return "CON"  # Connection established (SYN-ACK flags set)
    elif flags & flag_ack and not flags & flag_syn and not flags & flag_fin:
        return "ESTABLISHED"  # Only ACK flag set, connection established
    elif flags & flag_fin and flags & flag_ack:
        return "INT"  # Connection termination initiated (FIN-ACK flags set)
    elif flags & flag_fin and not flags & flag_ack:
        return "INT"  # Connection termination (FIN flag set)
    elif flags & flag_rst:
        return "INT"  # Connection reset (RST flag set)
    elif flags & flag_psh and flags & flag_ack:
        return "PUSH_ACK"  # Data being pushed (PSH-ACK flags set)
    elif flags & flag_ack and flags & flag_urg:
        return "URGENT"  # Urgent data (ACK and URG flags set)
    elif flags & flag_ece and flags & flag_cwr:
        return "ECE_CWR"  # Congestion control (ECE and CWR flags set)
    elif flags == 0:
        return "CLOSED"  # No flags set, connection closed

    return "UNKNOWN"

def get_the_state_con(packet):
    state = get_packet_state(packet)

    STATE_CON=0
    if state == "CON":
        STATE_CON=1
    
    return STATE_CON

def get_the_state_int(packet):
    state = get_packet_state(packet)
    
    STATE_INT=0
    if state == "INT":
        STATE_INT=1
    
    return STATE_INT
        
    
   
def ct_srv_src(pkt_info,service_port,source_ip):
    global packet_window
    packet_window.append(pkt_info)
    count = sum(1 for pkt in packet_window if pkt['src_ip'] == source_ip and pkt['service'] == service_port)
    scaled_count=count/2193.0
    print(f"Number of connections with service port {service_port} and source IP {source_ip}: {count}")


def ct_dst_itm(pkt_info,destination_ip):
    packet_window.append(pkt_info)
    count=sum(1 for pkt in packet_window if pkt['dst_ip'] == destination_ip)
    scaled_count=count*0.01
    print(f"Number of connections of the same destination address {destination_ip}: {count}")


def ct_src_dport_ltm(pkt_info,source_ip,destination_port):
    packet_window.append(pkt_info)
    count=sum(1 for pkt in packet_window if pkt['src_ip'] == source_ip and pkt['dst_port'] == destination_port)
    print(f"Number of connections of the same source address {source_ip} and the destination port {destination_port}: {count}")
    scaled_count=count*0.0025

def ct_dst_sport_ltm(pkt_info,destination_ip,source_port):
    packet_window.append(pkt_info)
    count=sum(1 for pkt in packet_window if pkt['dst_ip'] == destination_ip and pkt['src_port'] == source_port)
    print(f"Number of connections of the same destination address {destination_ip} and the source port{source_port}: {count}")
    scaled_count=count*0.0333333333333333

def ct_dst_src_ltm(pkt_info,source_ip,destination_ip):
    packet_window.append(pkt_info)
    count=sum(1 for pkt in packet_window if pkt['dst_ip'] == destination_ip and pkt['src_ip'] == source_ip)
    print(f"Number of connections of the same destination address {destination_ip} and the source address {source_ip}: {count}")
    scaled_count=count*0.0196078431372549

def ct_src_ltm(pkt_info,source_ip):
    packet_window.append(pkt_info)
    count=sum(1 for pkt in packet_window if pkt['src_ip'] == source_ip)
    scaled_count=count*0.0084745762711864
    print(f"Number of connections of the same source address {source_ip}: {count}")

def ct_srv_dst(pkt_info,service_port,destination_ip):
    packet_window.append(pkt_info)
    count = sum(1 for pkt in packet_window if pkt['dst_ip'] == destination_ip and pkt['service'] == service_port)
    scaled_count=count/0.0010050505050505
    print(f"Number of connections with service port {service_port} and destibation IP {destination_ip}: {count}")


def extract_service(packet):
    service = None 

    # Check for common application layer protocols
    if 'HTTPS' in packet:
        service = 'HTTPS'
    elif 'DNS' in packet:
        service = 'DNS'
    elif 'FTP' in packet:
        service = 'FTP'
    elif 'ICMP' in packet:
        service = 'ICMP'
    elif 'SMTP' in packet:
        service = 'SMTP'
    elif 'IMAP' in packet:
        service = 'IMAP'
    elif 'POP' in packet:
        service = 'POP'
    elif 'SSH' in packet:
        service = 'SSH'
    elif 'TELNET' in packet:
        service = 'TELNET'
    elif 'TLS' in packet:
        service = 'TLS'
    elif 'SMB' in packet:
        service = 'SMB'
    elif 'RDP' in packet:
        service = 'RDP'

    # Add more protocols as needed

    return service
    

def analyze_packet(packet, malicious_ips, snort_rules, packet_queue):
    global total_data, start_time
    # Initialize start time if it's the first packet
    if start_time is None:
        start_time = datetime.now()
    if hasattr(packet, 'ip'):
        if packet.transport_layer == 'TCP':
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
        elif packet.transport_layer == 'UDP':
            src_port = packet.udp.srcport
            dst_port = packet.udp.dstport
        else:
            src_port = dst_port = None

        

        packet_info = {
            'src_ip': packet.ip.src,
            'dst_ip': packet.ip.dst,
            'protocol': packet.transport_layer if hasattr(packet, 'transport_layer') else 'any',
            'payload': packet.highest_layer,
            'timestamp': datetime.now().isoformat(),
            'ttl': packet.ip.ttl,
            'dst_port': dst_port,
            'src_port': src_port,
            'service': extract_service(packet),
            'state' : get_packet_state(packet)
            
        }
        x1= ct_srv_src(packet_info,extract_service(packet),packet.ip.src)
        x3= ct_dst_itm(packet_info,packet.ip.dst)
        x4= ct_src_dport_ltm(packet_info,packet.ip.src,dst_port)
        x5= ct_dst_sport_ltm(packet_info,packet.ip.dst,src_port)
        x6= ct_dst_src_ltm(packet_info,packet.ip.src,packet.ip.dst)
        x7= ct_src_ltm(packet_info,packet.ip.src)
        x8= ct_srv_dst(packet_info,extract_service(packet),packet.ip.dst)
        x9= get_the_state_con(packet)
        x10= get_the_state_int(packet)


        ttl=int(packet.ip.ttl)
        scaled_ttl=ttl*0.002232142857142857

        # Calculate packet length and add to total data
        packet_length = int(packet.length)
        total_data += packet_length
        # Calculate the duration since the start time
        current_time = datetime.now()
        duration = (current_time - start_time).total_seconds()

        # Calculate data flow rate (bytes per second)
        if duration > 0:
            rate = total_data / duration
        else:
            rate = 0
        # Apply the scaling factor
        scaling_factor = 8.428885017607458e-06
        scaled_rate = rate * scaling_factor
        sload=rate*8
        scaled_sload=scaled_rate*8
        packet_info['sload']=sload
        packet_info['rate'] = rate
        features=[scaled_rate,scaled_ttl,scaled_sload,scaled_sload,x1,0,x3,x4,x5,x6,x7,x8,x9,x10]
    
        print(f"Analyzing packet: {packet_info}")
        store_log(packet_info)
        packet_queue.put({'type': 'log', 'data': packet_info})

        # Check against malicious IPs
        if packet_info['src_ip'] in malicious_ips or packet_info['dst_ip'] in malicious_ips:
            threat_info = {**packet_info, 'threat': {'severity': 'High'}}
            print(f"Malicious IP detected: {threat_info}")
            store_log(threat_info)
            trigger_alert(packet_queue, threat_info)
            return  # Skip Snort rules if a malicious IP is detected
        
        # Check against Snort rules
        snort_rule_matched = False
        for rule in snort_rules:
             if 'protocol' not in rule:
                continue
            # Debug: Print the rule being processed
             if (rule['protocol'] == packet_info['protocol'] or rule['protocol'] == 'any') and \
               (rule['source'] == 'any' or rule['source'] == packet_info['src_ip']) and \
               (rule['destination'] == 'any' or rule['destination'] == packet_info['dst_ip']):
                
                # Extract options from the rule
                options = extract_options(rule.get('options', ''))
                
                # Match options against packet data
                if match_options(options, packet.highest_layer):
                    threat_info = {**packet_info, 'threat': rule}
                    print(f"Snort rule matched: {threat_info}")
                    store_log(threat_info)
                    trigger_alert(packet_queue, threat_info)
                    snort_rule_matched = True
                    break
        # If no Snort rule matches, pass the packet to the AI model
        if not snort_rule_matched  :
            # Load the model
            joblib_file = 'E:\\gp\\mlp_binary3.pkl'
            model = joblib.load(joblib_file)
            input_data = np.array(features).reshape(1,-1)
            predict=model.predict(input_data)
            # Handle the predictions
            if predict==0:  
                threat_info = {**packet_info, 'threat': {'severity': 'Moderate', 'source': 'AI Model'}}
                print(f"AI model detected potential threat: {threat_info}")
                store_log(threat_info)
                trigger_alert(packet_queue, threat_info)
            else:
                print("NORMAL")

def capture_packets_live(snort_rules, malicious_ips, interface, packet_queue, stop_event):
    print(f"Starting live capture on interface: {interface}")
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.LiveCapture(interface=interface)
    for packet in capture.sniff_continuously(packet_count=40):
        if stop_event.is_set():
            break
        analyze_packet(packet, malicious_ips, snort_rules, packet_queue)

def capture_packets_file(snort_rules, malicious_ips, file_path, packet_queue, stop_event):
    if not os.path.exists(file_path):
        print(f"Capture file not found: {file_path}. Skipping file capture.")
        return

    print(f"Starting file capture from file: {file_path}")
    asyncio.set_event_loop(asyncio.new_event_loop())
    capture = pyshark.FileCapture(file_path)
    for packet in capture:
        if stop_event.is_set():
            break
        analyze_packet(packet, malicious_ips, snort_rules, packet_queue)

def start_packet_capture(snort_rules, malicious_ips, network_interface, capture_methods, capture_file_path, packet_queue, stop_event):
    threads = []

    if "live" in capture_methods:
        t_live = threading.Thread(target=capture_packets_live, args=(snort_rules, malicious_ips, network_interface, packet_queue, stop_event))
        threads.append(t_live)

    if "file" in capture_methods and os.path.exists(capture_file_path):
        t_file = threading.Thread(target=capture_packets_file, args=(snort_rules, malicious_ips, capture_file_path, packet_queue, stop_event))
        threads.append(t_file)

    for thread in threads:
        thread.start()

    return threads

def run_ids_capture(packet_queue, stop_event):
    try:
        snort_rules = fetch_snort_rules()
        malicious_ips = fetch_malicious_ips()
        print("Starting packet capture...")
        threads = start_packet_capture(snort_rules, malicious_ips, network_interface, capture_methods, capture_file_path, packet_queue, stop_event)
        return threads
    except Exception as e:
        error_info = {'error': str(e), 'timestamp': datetime.now().isoformat()}
        store_log(error_info)
        packet_queue.put({'type': 'log', 'data': error_info})
        return []

# Example usage
if __name__ == "__main__":
    packet_queue = queue.Queue()
    stop_event = threading.Event()
    threads = run_ids_capture(packet_queue, stop_event)
    
    try:
        while True:
            packet_info = packet_queue.get()
            print(packet_info)
    except KeyboardInterrupt:
        stop_event.set()
        for thread in threads:
            thread.join()
