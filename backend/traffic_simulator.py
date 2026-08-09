"""
NetShield AI - Traffic Telemetry Simulator
Generates realistic multi-source network packet streams and attack scenarios.
Scenarios: Normal, SSH Brute Force, DDoS SYN Flood, Ransomware C2, Data Exfiltration, Port Scan.
"""

import random
import time
from typing import Dict, Any, List
from backend.models import LogEntry, PacketFeature

class TrafficSimulator:
    def __init__(self):
        self.current_scenario = "Normal Baseline"
        self.devices = [
            {"id": "DEV-001", "name": "Router-01", "ip": "192.168.1.1", "type": "Router", "risk": 12.0, "predicted": 15.0},
            {"id": "DEV-002", "name": "Web Server-02", "ip": "10.0.0.5", "type": "Server", "risk": 96.0, "predicted": 97.0},
            {"id": "DEV-003", "name": "Production DB-01", "ip": "10.0.0.12", "type": "Database", "risk": 78.0, "predicted": 88.0},
            {"id": "DEV-004", "name": "User Laptop-04", "ip": "192.168.1.45", "type": "Workstation", "risk": 68.0, "predicted": 72.0},
            {"id": "DEV-005", "name": "Smart Camera-09", "ip": "192.168.1.88", "type": "IoT", "risk": 15.0, "predicted": 18.0}
        ]

    def set_scenario(self, scenario_name: str):
        self.current_scenario = scenario_name

    def generate_stream(self) -> Dict[str, Any]:
        logs = []
        now_time = time.strftime("%H:%M:%S")

        if self.current_scenario == "SSH Brute Force":
            for i in range(12):
                logs.append(LogEntry(
                    id=f"log_bf_{i}",
                    timestamp=now_time,
                    source_ip="185.220.101.5",
                    destination_ip="10.0.0.5",
                    source_port=51200 + i,
                    destination_port=22,
                    protocol="SSH",
                    log_type="Syslog",
                    action="FAILED_LOGIN",
                    payload_size=128,
                    raw_text=f"{now_time} sshd[4912]: Failed password for invalid user admin from 185.220.101.5 port {51200+i} ssh2"
                ))
            feature = PacketFeature(packet_rate=12.5, byte_rate=2400.0, failed_logins=12, dns_anomalies=0, distinct_dst_ports=1, payload_entropy=2.1, connection_duration=1.2, is_known_malicious_ip=True)

        elif self.current_scenario == "DDoS Attack":
            for i in range(25):
                logs.append(LogEntry(
                    id=f"log_ddos_{i}",
                    timestamp=now_time,
                    source_ip=f"198.51.100.{random.randint(1, 250)}",
                    destination_ip="10.0.0.5",
                    source_port=random.randint(1024, 65535),
                    destination_port=80,
                    protocol="TCP-SYN",
                    log_type="Suricata",
                    action="ALERT",
                    payload_size=1460,
                    raw_text=f"{now_time} SURICATA [1:2000001:1] ET DDoS SYN Flood Detection"
                ))
            feature = PacketFeature(packet_rate=850.0, byte_rate=1250000.0, failed_logins=0, dns_anomalies=0, distinct_dst_ports=1, payload_entropy=1.5, connection_duration=0.1, is_known_malicious_ip=True)

        elif self.current_scenario == "Data Exfiltration":
            for i in range(8):
                logs.append(LogEntry(
                    id=f"log_exfil_{i}",
                    timestamp=now_time,
                    source_ip="10.0.0.12",
                    destination_ip="91.240.118.172",
                    source_port=54321,
                    destination_port=443,
                    protocol="HTTPS/TLS",
                    log_type="Zeek",
                    action="ALLOW",
                    payload_size=250000,
                    raw_text=f"{now_time} Zeek Conn: High Volume Encrypted Stream to 91.240.118.172"
                ))
            feature = PacketFeature(packet_rate=45.0, byte_rate=850000.0, failed_logins=0, dns_anomalies=2, distinct_dst_ports=1, payload_entropy=4.9, connection_duration=45.0, is_known_malicious_ip=True)

        else: # Normal Baseline
            for i in range(5):
                logs.append(LogEntry(
                    id=f"log_norm_{i}",
                    timestamp=now_time,
                    source_ip="192.168.1.45",
                    destination_ip="10.0.0.5",
                    source_port=53210 + i,
                    destination_port=443,
                    protocol="HTTPS",
                    log_type="Syslog",
                    action="ALLOW",
                    payload_size=1420,
                    raw_text=f"{now_time} firewall: ACCEPT src=192.168.1.45 dst=10.0.0.5 proto=HTTPS"
                ))
            feature = PacketFeature(packet_rate=2.1, byte_rate=3500.0, failed_logins=0, dns_anomalies=0, distinct_dst_ports=2, payload_entropy=1.8, connection_duration=12.0, is_known_malicious_ip=False)

        return {
            "scenario": self.current_scenario,
            "timestamp": now_time,
            "logs": logs,
            "features": feature
        }
