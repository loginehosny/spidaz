# test_packets.py

def get_test_packets():
    return [
        {
            'Number of Packet': 1,
            'dst_ip': '192.168.0.1',
            'src_ip': '10.0.0.1',
            'payload': 'Test Payload 1',
            'protocol': 'TCP',
            'timestamp': '2024-05-24 12:00:00',
            'threat_detected': True
        },
        {
            'Number of Packet': 2,
            'dst_ip': '192.168.0.2',
            'src_ip': '10.0.0.2',
            'payload': 'Test Payload 2',
            'protocol': 'UDP',
            'timestamp': '2024-05-24 12:01:00',
            'threat_detected': False
        },
        {
            'Number of Packet': 3,
            'dst_ip': '192.168.0.3',
            'src_ip': '10.0.0.3',
            'payload': 'Test Payload 3',
            'protocol': 'TCP',
            'timestamp': '2024-05-24 12:02:00',
            'threat_detected': True
        }
    ]
