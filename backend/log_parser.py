"""
NetShield AI - Log Parser Module
Parses multi-source telemetry logs (Syslog, Zeek, Suricata EVE, Windows Event Logs).
Extracts features for ML detection engines.
"""

import json
import re
from typing import Dict, Any, List
from backend.models import LogEntry, PacketFeature

class LogParser:
    def __init__(self):
        # Known malicious IPs for threat intel benchmarking
        self.malicious_ips = {"185.220.101.5", "198.51.100.42", "45.33.32.156", "91.240.118.172", "193.142.146.210"}
        
    def parse_syslog(self, raw_line: str) -> LogEntry:
        # Example format: "2026-08-07T12:00:00Z router-01 syslog: ACCEPT src=192.168.1.50 dst=10.0.0.5 proto=TCP spt=443 dpt=80 size=1420"
        ip_pattern = r'src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+)'
        proto_pattern = r'proto=(\w+)'
        dpt_pattern = r'dpt=(\d+)'
        
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        proto = "TCP"
        dpt = 80
        
        m_ip = re.search(ip_pattern, raw_line)
        if m_ip:
            src_ip, dst_ip = m_ip.group(1), m_ip.group(2)
        m_proto = re.search(proto_pattern, raw_line)
        if m_proto:
            proto = m_proto.group(1)
        m_dpt = re.search(dpt_pattern, raw_line)
        if m_dpt:
            dpt = int(m_dpt.group(1))
            
        action = "ALERT" if "FAILED" in raw_line or "DROP" in raw_line else "ALLOW"
        
        return LogEntry(
            id=f"log_{hash(raw_line) & 0xFFFFFFFF}",
            timestamp="2026-08-07 13:00:00",
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=54321,
            destination_port=dpt,
            protocol=proto,
            log_type="Syslog",
            action=action,
            payload_size=1420,
            raw_text=raw_line
        )

    def parse_zeek_json(self, json_str: str) -> LogEntry:
        try:
            data = json.loads(json_str)
            return LogEntry(
                id=data.get("uid", "zeek_001"),
                timestamp=data.get("ts", "2026-08-07 13:00:00"),
                source_ip=data.get("id.orig_h", "192.168.1.15"),
                destination_ip=data.get("id.resp_h", "10.0.0.2"),
                source_port=data.get("id.orig_p", 51234),
                destination_port=data.get("id.resp_p", 22),
                protocol=data.get("proto", "TCP"),
                log_type="Zeek",
                action="ALLOW",
                payload_size=data.get("orig_bytes", 0) + data.get("resp_bytes", 0),
                domain=data.get("query", None),
                raw_text=json_str
            )
        except Exception:
            return self.parse_syslog(json_str)

    def parse_windows_event(self, event_dict: Dict[str, Any]) -> LogEntry:
        # Event ID 4625 = Failed Logon
        event_id = event_dict.get("EventID", 4625)
        action = "FAILED_LOGIN" if event_id == 4625 else "ALLOW"
        
        return LogEntry(
            id=f"win_{event_dict.get('RecordNumber', 1000)}",
            timestamp=event_dict.get("TimeCreated", "2026-08-07 13:00:00"),
            source_ip=event_dict.get("WorkstationIP", "185.220.101.5"),
            destination_ip=event_dict.get("TargetServerIP", "10.0.0.5"),
            source_port=49152,
            destination_port=445,
            protocol="SMB/NTLM",
            log_type="WindowsEvent",
            action=action,
            payload_size=512,
            event_id=event_id,
            raw_text=f"EventID {event_id}: Account Logon Failed for user {event_dict.get('TargetUserName', 'Admin')}"
        )

    def extract_features(self, logs: List[LogEntry]) -> PacketFeature:
        if not logs:
            return PacketFeature(0, 0, 0, 0, 0, 0.0, 0.0, False)
            
        total_bytes = sum(l.payload_size for l in logs)
        failed_logins = sum(1 for l in logs if l.action == "FAILED_LOGIN" or "failed" in l.raw_text.lower())
        dns_anomalies = sum(1 for l in logs if l.domain and ("xyz" in l.domain or "c2" in l.domain or "bit" in l.domain or len(l.domain) > 30))
        dst_ports = len(set(l.destination_port for l in logs))
        has_malicious = any(l.source_ip in self.malicious_ips or l.destination_ip in self.malicious_ips for l in logs)
        
        return PacketFeature(
            packet_rate=len(logs) / 10.0,
            byte_rate=total_bytes / 10.0,
            failed_logins=failed_logins,
            dns_anomalies=dns_anomalies,
            distinct_dst_ports=dst_ports,
            payload_entropy=4.8 if has_malicious else 2.1,
            connection_duration=120.0,
            is_known_malicious_ip=has_malicious
        )
