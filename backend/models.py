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
    confidence_score: float  # 0.0 to 1.0
    risk_score: float        # 0.0 to 100.0
    severity: str            # Critical, High, Medium, Low
    mitre_technique_id: str  # e.g., T1110
    mitre_technique_name: str # e.g., Brute Force
    xai_reasons: List[str]
    raw_logs: List[str]
    geo_country: str = "Unknown"
    malware_family: str = "N/A"
    is_mitigated: bool = False
    mitigation_action: str = ""

@dataclass
class DeviceRiskProfile:
    device_id: str
    name: str
    ip_address: str
    device_type: str  # Router, Firewall, Server, Workstation, IoT
    current_risk_score: float  # 0 to 100%
    predicted_risk_24h: float  # 0 to 100%
    threat_status: str         # Safe, Suspicious, Compromised
    active_threats: int
    last_updated: str
    factors: List[str] = field(default_factory=list)

@dataclass
class AttackGraphNode:
    id: str
    label: str
    type: str  # Internet, Firewall, Server, Database, Workstation
    ip: str
    status: str # Safe, Suspicious, Compromised
    risk_score: float

@dataclass
class AttackGraphEdge:
    source: str
    target: str
    protocol: str
    status: str # Normal, Anomaly, AttackPath

@dataclass
class IncidentReport:
    report_id: str
    generated_at: str
    target_device: str
    risk_score: float
    confidence_score: float
    executive_summary: str
    timeline: List[Dict[str, Any]]
    xai_evidence: List[str]
    mitre_mappings: List[Dict[str, str]]
    recommended_actions: List[str]
    soar_actions_taken: List[str]
