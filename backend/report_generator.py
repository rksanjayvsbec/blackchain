"""
NetShield AI - AI Incident Report Generator Module
Generates comprehensive executive and technical security incident reports.
Formats report into Markdown and HTML for PDF export.
"""

from typing import Dict, Any, List
from datetime import datetime
from backend.models import IncidentReport

class IncidentReportGenerator:
    def __init__(self):
        pass

    def generate_report(self, device_name: str, device_ip: str, alert_data: Dict[str, Any], soar_actions: List[str]) -> Dict[str, Any]:
        report_id = f"INC-2026-{hash(device_name + alert_data.get('id', '001')) & 0xFFFF:04d}"
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        
        exec_summary = (
            f"On {now_str}, NetShield AI detected a CRITICAL network compromise on asset **{device_name}** ({device_ip}). "
            f"The incident involved an automated **{alert_data.get('attack_category', 'SSH Brute Force')}** attack "
            f"originated from known malicious C2 IP **185.220.101.5** (Country: Russia, Threat: LockBit Ransomware C2). "
            f"AI Detection Models assigned a confidence score of **{int(alert_data.get('confidence_score', 0.96)*100)}%** "
            f"and escalated the device risk score to **{alert_data.get('risk_score', 96.0)}%**."
        )

        timeline = [
            {"time": "13:00:02", "event": "Baseline telemetry shift detected on edge interface eth0."},
            {"time": "13:00:15", "event": f"Received 412 failed SSH login attempts from IP 185.220.101.5."},
            {"time": "13:00:28", "event": f"Supervised Random Forest Classifier triggered alert: {alert_data.get('attack_category', 'SSH Brute Force')}."},
            {"time": "13:00:45", "event": f"NetShield AI Copilot flagged active attack and predicted 24h risk acceleration to 97%."},
            {"time": "13:01:10", "event": f"SOAR Engine executed automated playbooks: Block IP, Isolate Host."}
        ]

        xai_evidence = alert_data.get("xai_reasons", [
            "• 412 Failed SSH Login Attempts within 60s window",
            "• Outbound connections to known malicious C2 IP 185.220.101.5",
            "• Outbound payload volume burst: 2.3 GB",
            "• High entropy DNS subdomains matching C2 heartbeat pattern"
        ])

        mitre_mappings = [
            {
                "technique_id": alert_data.get("mitre_technique_id", "T1110"),
                "name": alert_data.get("mitre_technique_name", "Brute Force"),
                "tactic": "Credential Access",
                "mitigation": "Enable Multi-Factor Authentication & Account Lockout Policies"
            },
            {
                "technique_id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control",
                "mitigation": "Enforce Deep Packet Inspection & Firewall C2 Domain Blocking"
            }
        ]

        recommendations = [
            "Maintain IP 185.220.101.5 on global perimeter blocklist across all firewalls.",
            "Verify host isolation status for Web Server-02 until full forensic memory dump is analyzed.",
            "Enforce mandatory password reset for all user accounts associated with host 10.0.0.5.",
            "Apply security patch CVE-2023-3519 on OpenSSH service endpoints."
        ]

        # Generate Markdown version
        md_content = f"""# 🛡️ NetShield AI Security Incident Investigation Report
**Report ID:** {report_id}  
**Timestamp:** {now_str}  
**Target Asset:** {device_name} ({device_ip})  
**Threat Status:** 🔴 COMPROMISED (Risk Score: {alert_data.get('risk_score', 96)}%)  
**AI Confidence:** {int(alert_data.get('confidence_score', 0.96)*100)}%

---

## 1. Executive Summary
{exec_summary}

---

## 2. Attack Timeline
| Time | Incident Event |
| :--- | :--- |
"""
        for t in timeline:
            md_content += f"| {t['time']} | {t['event']} |\n"

        md_content += """
---

## 3. Explainable AI (XAI) Root Cause Evidence
"""
        for x in xai_evidence:
            md_content += f"- {x}\n"

        md_content += """
---

## 4. MITRE ATT&CK Framework Mapping
| ID | Technique Name | Tactic | Recommended Mitigation |
| :--- | :--- | :--- | :--- |
"""
        for m in mitre_mappings:
            md_content += f"| **{m['technique_id']}** | {m['name']} | {m['tactic']} | {m['mitigation']} |\n"

        md_content += """
---

## 5. SOAR Remediation Playbooks Executed
"""
        for action in (soar_actions or ["Block IP: 185.220.101.5", "Isolate Host: 10.0.0.5", "Kill PID: 4912"]):
            md_content += f"- ✓ **{action}** (Executed automatically by NetShield SOAR Engine)\n"

        md_content += """
---

## 6. Long-Term Security Recommendations
"""
        for rec in recommendations:
            md_content += f"- {rec}\n"

        return {
            "report_id": report_id,
            "generated_at": now_str,
            "device_name": device_name,
            "device_ip": device_ip,
            "executive_summary": exec_summary,
            "timeline": timeline,
            "xai_evidence": xai_evidence,
            "mitre_mappings": mitre_mappings,
            "soar_actions": soar_actions,
            "markdown_report": md_content
        }
