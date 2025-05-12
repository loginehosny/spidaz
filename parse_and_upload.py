import re
import json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

# Define the paths to the files
snort_rules_file_path = r'D:\My downloads\snort3-community-rules\snort3-community-rules\snort3-community.rules'
json_file_path = r'D:\My downloads\snort3-community-rules\snort3-community-rules\snort3-community-rules.json'
firebase_credential_path = r'E:\gp\serviceAccountKey.json'

# Function to parse a Snort rule
def parse_snort_rule(rule):
    rule_pattern = re.compile(r'^(alert|log|pass|activate|dynamic|drop|reject|sdrop) ' +
                              r'(icmp|tcp|udp|ip) ' +
                              r'(\$EXTERNAL_NET|\d+\.\d+\.\d+\.\d+|\$HOME_NET|\$HTTP_SERVERS|\$SMTP_SERVERS|\$SQL_SERVERS|\$TELNET_SERVERS) ' +
                              r'(\d+|any) ' +
                              r'-> ' +
                              r'(\$EXTERNAL_NET|\d+\.\d+\.\d+\.\d+|\$HOME_NET|\$HTTP_SERVERS|\$SMTP_SERVERS|\$SQL_SERVERS|\$TELNET_SERVERS) ' +
                              r'(\d+|any) ' +
                              r'\((.*)\)$')

    match = rule_pattern.match(rule)
    if match:
        action = match.group(1)
        protocol = match.group(2)
        source = match.group(3)
        source_port = match.group(4)
        destination = match.group(5)
        destination_port = match.group(6)
        options = match.group(7)

        return {
            'action': action,
            'protocol': protocol,
            'source': source,
            'source_port': source_port,
            'destination': destination,
            'destination_port': destination_port,
            'options': options
        }
    return None

# Step 1: Read and parse the Snort rules
try:
    with open(snort_rules_file_path, 'r') as file:
        rules = file.readlines()

    parsed_rules = []
    for rule in rules:
        parsed_rule = parse_snort_rule(rule.strip())
        if parsed_rule:
            parsed_rules.append(parsed_rule)

    # Convert parsed rules to JSON
    rules_json = json.dumps(parsed_rules, indent=4)

    # Save JSON to a file
    with open(json_file_path, 'w') as json_file:
        json_file.write(rules_json)

    print(f"Rules have been converted to JSON and saved to {json_file_path}")

except PermissionError as e:
    print(f"PermissionError: {e}")
except FileNotFoundError as e:
    print(f"FileNotFoundError: {e}")
except Exception as e:
    print(f"An error occurred: {e}")

# Step 2: Upload JSON data to Firebase Firestore
try:
    # Initialize Firebase app
    cred = credentials.Certificate(firebase_credential_path)
    firebase_admin.initialize_app(cred)

    # Initialize Firestore DB
    db = firestore.client()

    # Read JSON data
    with open(json_file_path, 'r') as json_file:
        rules_json = json.load(json_file)

    # Upload JSON data to Firestore
    for index, rule in enumerate(rules_json):
        doc_ref = db.collection('snort_rules').document(str(index))
        doc_ref.set(rule)

    print("Rules have been uploaded to Firebase Firestore")

except firebase_admin.exceptions.FirebaseError as e:
    print(f"FirebaseError: {e}")
except Exception as e:
    print(f"An error occurred: {e}")
