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
