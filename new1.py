import re
import json
import os

# Define the path to the Snort rules file
file_path = r'D:\My downloads\snort3-community-rules\snort3-community-rules'

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

# Check if the file exists
if not os.path.exists(file_path):
    print(f"File does not exist: {file_path}")
    exit(1)

# Open and read the file
try:
    with open(file_path, 'r') as file:
        rules = file.readlines()
except PermissionError as e:
    print(f"Permission error: {e}")
    exit(1)
except Exception as e:
    print(f"An error occurred: {e}")
    exit(1)

# Process each rule
parsed_rules = []
for rule in rules:
    parsed_rule = parse_snort_rule(rule.strip())
    if parsed_rule:
        parsed_rules.append(parsed_rule)

# Convert parsed rules to JSON
rules_json = json.dumps(parsed_rules, indent=4)

# Define the path to save the JSON file
json_file_path = r'D:\My downloads\snort3-community-rules\snort3-community-rules\snort3-community-rules.json'

# Ensure the directory exists
os.makedirs(os.path.dirname(json_file_path), exist_ok=True)

# Save JSON to a file
try:
    with open(json_file_path, 'w') as json_file:
        json_file.write(rules_json)
    print(f"Rules have been converted to JSON and saved to {json_file_path}")
except PermissionError as e:
    print(f"Permission error: {e}")
except Exception as e:
    print(f"An error occurred while saving the file: {e}")
