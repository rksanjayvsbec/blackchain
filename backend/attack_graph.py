"""
NetShield AI - Attack Graph Generator
Computes network topology nodes and attack propagation paths (lateral movement).
Statuses: 🟢 Safe, 🟠 Suspicious, 🔴 Compromised
"""

from typing import Dict, Any, List
from backend.models import AttackGraphNode, AttackGraphEdge

class AttackGraphEngine:
    def __init__(self):
        pass

    def build_network_graph(self, active_threats: List[Dict[str, Any]]) -> Dict[str, Any]:
        # Default infrastructure topology
        nodes = [
            {"id": "node_internet", "label": "External Internet", "type": "Internet", "ip": "0.0.0.0/0", "status": "Safe", "risk_score": 0},
            {"id": "node_fw", "label": "Edge Firewall", "type": "Firewall", "ip": "192.168.1.1", "status": "Safe", "risk_score": 15},
            {"id": "node_workstation", "label": "User Laptop-04", "type": "Workstation", "ip": "192.168.1.45", "status": "Suspicious", "risk_score": 68},
            {"id": "node_server2", "label": "Web Server-02", "type": "Server", "ip": "10.0.0.5", "status": "Compromised", "risk_score": 96},
            {"id": "node_db", "label": "Production DB-01", "type": "Database", "ip": "10.0.0.12", "status": "Suspicious", "risk_score": 78},
            {"id": "node_iot", "label": "Smart Camera-09", "type": "IoT", "ip": "192.168.1.88", "status": "Safe", "risk_score": 12}
        ]

        edges = [
            {"source": "node_internet", "target": "node_fw", "protocol": "WAN/HTTPS", "status": "Normal"},
            {"source": "node_fw", "target": "node_workstation", "protocol": "LAN/DHCP", "status": "Normal"},
            {"source": "node_fw", "target": "node_server2", "protocol": "HTTP/80", "status": "AttackPath"},
            {"source": "node_workstation", "target": "node_server2", "protocol": "SSH/22", "status": "AttackPath"},
            {"source": "node_server2", "target": "node_db", "protocol": "MySQL/3306", "status": "AttackPath"},
            {"source": "node_fw", "target": "node_iot", "protocol": "RTSP/554", "status": "Normal"}
        ]

        # Dynamically escalate node status based on active threats
        compromised_ips = {t.get("device_ip") for t in active_threats if t.get("severity") == "Critical"}
        suspicious_ips = {t.get("device_ip") for t in active_threats if t.get("severity") in ["High", "Medium"]}

        for n in nodes:
            if n["ip"] in compromised_ips:
                n["status"] = "Compromised"
                n["risk_score"] = max(n["risk_score"], 92)
            elif n["ip"] in suspicious_ips:
                n["status"] = "Suspicious"
                n["risk_score"] = max(n["risk_score"], 65)

        return {
            "nodes": nodes,
            "edges": edges,
            "attack_path_summary": "Infection Vector: External IP 185.220.101.5 ➔ Edge Firewall ➔ Web Server-02 (Compromised via SSH Brute Force) ➔ Attempted Lateral Probe to Production DB-01."
        }
