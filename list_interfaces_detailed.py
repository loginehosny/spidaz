from scapy.all import ifaces

# List all network interfaces with details
print("Available network interfaces:")
for iface in ifaces.values():
    print(f"Name: {iface.name}, Description: {iface.description}, MAC: {iface.mac}")
