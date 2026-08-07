"""
NetShield AI - Core Models & Data Structures
Defines telemetry schemas, risk profiles, alert objects, attack graph structures, and incident report data models.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import json

@dataclass
class LogEntry:
    id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str  # TCP, UDP, ICMP, HTTP, DNS, SSH
    log_type: str  # Syslog, Zeek, Suricata, WindowsEvent
    action: str    # ALLOW, DROP, ALERT, FAILED_LOGIN
    payload_size: int
    domain: Optional[str] = None
    event_id: Optional[int] = None
    raw_text: str = ""

@dataclass
class PacketFeature:
    packet_rate: float
    byte_rate: float
    failed_logins: int
    dns_anomalies: int
    distinct_dst_ports: int
    payload_entropy: float
    connection_duration: float
    is_known_malicious_ip: bool

@dataclass
class ThreatAlert:
    id: str
    timestamp: str
    device_id: str
    device_name: str
    device_ip: str
    attack_category: str  # DDoS, Malware, SSH Brute Force, Port Scan, Data Exfiltration, Suspicious DNS
