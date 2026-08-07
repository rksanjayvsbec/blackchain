"""
NetShield AI - Threat Intelligence Engine
Provides GeoIP reputation, CVE lookup, Malware Family classification, and MITRE ATT&CK Framework Mapping.
"""

from typing import Dict, Any, Optional

class ThreatIntelligenceEngine:
    def __init__(self):
        # Threat intel database mock
        self.known_malicious_ips = {
            "185.220.101.5": {"country": "Russia", "threat": "LockBit Ransomware C2", "mitre_id": "T1071", "cve": "CVE-2023-3519"},
            "198.51.100.42": {"country": "China", "threat": "Mirai Botnet DDoS", "mitre_id": "T1498", "cve": "CVE-2022-26134"},
            "45.33.32.156": {"country": "North Korea", "threat": "Lazarus SSH Brute Force", "mitre_id": "T1110", "cve": "CVE-2023-23397"},
            "91.240.118.172": {"country": "Netherlands", "threat": "Cobalt Strike Beacon", "mitre_id": "T1048", "cve": "CVE-2021-44228"},
            "193.142.146.210": {"country": "Romania", "threat": "Emotet Loader", "mitre_id": "T1566", "cve": "CVE-2023-38831"}
        }
        
        self.mitre_db = {
            "T1110": {
                "name": "Brute Force",
                "tactic": "Credential Access",
                "description": "Adversaries may use brute force techniques to gain access to accounts by systematically guessing passwords.",
                "mitigations": ["Enable Multi-Factor Authentication (MFA)", "Implement Account Lockout Policies", "Rate limit login attempts"]
            },
            "T1498": {
                "name": "Network Denial of Service",
                "tactic": "Impact",
                "description": "Adversaries may perform Network DoS attacks to degrade or disrupt availability of services.",
                "mitigations": ["Deploy Anti-DDoS Firewall Protection", "Filter ICMP / SYN Floods", "Enable Cloudflare/AWS Shield Scrubbing"]
            },
            "T1071": {
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using application layer protocols to blend in with normal network traffic.",
                "mitigations": ["Enforce Deep Packet Inspection (DPI)", "Block Known Malicious C2 Domains/IPs", "Restrict Outbound Port 80/443 Traffic"]
            },
            "T1048": {
                "name": "Exfiltration Over Alternative Protocol",
                "tactic": "Exfiltration",
                "description": "Adversaries may steal data by transferring it over a different protocol or encrypted tunnel.",
                "mitigations": ["Data Loss Prevention (DLP) Inspection", "Strict Outbound Firewall Egress Rules", "Monitor High-Volume Transfers"]
            },
            "T1046": {
                "name": "Network Service Discovery",
                "tactic": "Discovery",
                "description": "Adversaries may attempt to get a listing of services running on remote hosts (Port Scanning).",
                "mitigations": ["Disable Unnecessary Listening Services", "Configure Network Micro-segmentation", "Alert on Port Scan Velocity"]
            },
            "T1071.004": {
                "name": "DNS Tunneling",
                "tactic": "Command and Control",
                "description": "Adversaries may communicate using DNS queries to hide data in TXT/AAAA records.",
                "mitigations": ["Enforce DNS Sinkholing", "Monitor High Entropy Subdomains", "Use Secure DNS (DoH/DoT) Gateway"]
            }
        }

    def lookup_ip(self, ip_address: str) -> Dict[str, Any]:
        if ip_address in self.known_malicious_ips:
            info = self.known_malicious_ips[ip_address]
            mitre_info = self.mitre_db.get(info["mitre_id"], {})
            return {
                "ip": ip_address,
                "is_malicious": True,
                "country": info["country"],
                "threat": info["threat"],
                "cve": info["cve"],
                "mitre_id": info["mitre_id"],
                "mitre_name": mitre_info.get("name", "Unknown"),
                "mitre_tactic": mitre_info.get("tactic", "Unknown"),
                "mitigations": mitre_info.get("mitigations", [])
            }
        return {
            "ip": ip_address,
            "is_malicious": False,
            "country": "Local / Internal",
            "threat": "Clean",
            "cve": "N/A",
            "mitre_id": "N/A",
            "mitre_name": "N/A",
            "mitre_tactic": "N/A",
            "mitigations": []
        }

    def get_mitre_mapping(self, technique_id: str) -> Dict[str, Any]:
        return self.mitre_db.get(technique_id, {
            "name": "General Anomaly",
            "tactic": "Defense Evasion",
            "description": "Behavior deviates significantly from baseline profile.",
            "mitigations": ["Isolate Device", "Investigate Process Tree", "Review Audit Logs"]
        })
