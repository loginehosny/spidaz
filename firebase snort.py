import json
import os
import re

def parse_snort_rule(rule):
    pattern = r'(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)\s*\((.*)\)'
    match = re.match(pattern, rule)
    
    if not match:
        return None
    
    action, protocol, src_ip, src_port, direction, dest_port, options = match.groups()
    
    options_dict = {}
    options = options.split(';')
    for option in options:
        if ":" in option:
            key, value = option.split(":", 1)
            options_dict[key.strip()] = value.strip()
    
    return {
        "action": action,
        "protocol": protocol,
        "source_ip": src_ip,
        "source_port": src_port,
        "direction": direction,
        "destination_ip": "any",
        "destination_port": dest_port,
        "options": options_dict
    }

def snort_rules_to_json(rules_directory, output_file):
    rules_list = []
    for filename in os.listdir(rules_directory):
        if filename.endswith(".rules"):
            with open(os.path.join(rules_directory, filename), 'r') as f:
                rules = f.readlines()
                for rule in rules:
                    rule = rule.strip()
                    if rule and not rule.startswith("#"):
                        parsed_rule = parse_snort_rule(rule)
                        if parsed_rule:
                            rules_list.append(parsed_rule)

    with open(output_file, 'w') as f:
        json.dump(rules_list, f, indent=2)

# Usage
snort_rules_to_json('D:\My downloads\snort-2.9.20\preproc_rules', 'snort_rules.json')
