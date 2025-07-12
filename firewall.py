from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime
import subprocess

# Define rules
import json

def load_rules():
    with open("rules.json", "r") as f:
        return json.load(f)

firewall_rules = load_rules()


# Apply iptables rules at system level
def apply_iptables_rules(rules):
    print("[*] Applying iptables rules...")

    for ip in rules["blocked_ips"]:
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

    for port in rules["blocked_ports"]:
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-j", "DROP"])
        subprocess.call(["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", str(port), "-j", "DROP"])

    print("[*] iptables rules applied.")

# Logging
def log_packet(packet, reason):
    with open("firewall_log.txt", "a") as logfile:
        logfile.write(f"[{datetime.now()}] {reason} -> {packet.summary()}\n")

# Rule checker
def check_rules(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto

        if src_ip in firewall_rules["blocked_ips"]:
            return "BLOCKED: Source IP"

        if TCP in packet:
            dport = packet[TCP].dport
            if dport in firewall_rules["blocked_ports"]:
                return "BLOCKED: TCP Port"
        elif UDP in packet:
            dport = packet[UDP].dport
            if dport in firewall_rules["blocked_ports"]:
                return "BLOCKED: UDP Port"
        elif ICMP in packet:
            return "BLOCKED: ICMP Ping"

        if proto in firewall_rules["blocked_protocols"]:
            return "BLOCKED: Protocol"

    return "ALLOWED"

# Callback for sniff
def packet_callback(packet):
    decision = check_rules(packet)
    print(f"{decision} -> {packet.summary()}")
    if decision.startswith("BLOCKED"):
        log_packet(packet, decision)

# Main execution
if __name__ == "__main__":
    apply_iptables_rules(firewall_rules)
    print("[*] Firewall is running. Sniffing packets...")
    sniff(filter="ip", prn=packet_callback, store=0)

