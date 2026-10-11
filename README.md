# NetShield AI / Blackchain 🛡️
### Autonomous Network Compromise Detection & Zero-Trust Defense Platform

NetShield AI is an intelligent, full-stack cybersecurity operations platform designed to detect network intrusions, model cyber compromise pathways in real-time, explain AI detection decisions (XAI), and automate incident containment (SOAR).

---

## 🌟 Key Features

- **Multi-Source Network Telemetry Ingestion**
  - Live ARP sweep & active subnet host discovery using Scapy.
  - Multi-vendor log parsing: Syslog, Zeek, Suricata, and Windows Security Event Logs.
  - Real-time network throughput and active listening socket monitoring.

- **Hybrid Machine Learning Detection Engine**
  - **Deep Autoencoder**: Unsupervised neural reconstruction error scoring for zero-day anomaly detection.
  - **Isolation Forest**: Multivariate hyperplane partitioning for high-dimensional telemetry outliers.
  - **Random Forest**: Multi-class supervised attack classification (DDoS, Port Scan, Ransomware, Brute-Force).

- **Dynamic MITRE ATT&CK Graph Synthesis**
  - Interactive topology and attack graph visualization.
  - Real-time blast-radius calculation and compromise trajectory prediction.

- **Security Orchestration, Automation & Response (SOAR)**
  - Automated containment playbooks.
  - One-click IP firewall isolation and quarantine.
  - Token revocation and adversary disruption.

- **Explainable AI (XAI)**
  - Feature attribution and SHAP breakdown modal for transparent decision auditing.

- **AI Security Copilot**
  - Embedded conversational analyst for threat investigations, remediation recommendations, and MITRE mapping.

- **Benchmark Datasets & Traffic Simulation**
  - Pre-integrated benchmark models and evaluation datasets: **CIC-IDS2017**, **TON_IoT**, and **UNSW-NB15**.
  - Synthetic adversary traffic playback (Brute Force, DDoS, Reconnaissance, Data Exfiltration).

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       NETSHIELD AI SOC                     │
│  [ Executive HUD ]   [ Topology Graph ]   [ Threat Table ]  │
│  [ Attack Graph ]    [ XAI Explainers ]   [ AI Copilot ]    │
└──────────────────────────────┬──────────────────────────────┘
                               │ HTTP / WebSocket REST API
┌──────────────────────────────▼──────────────────────────────┐
│                     BACKEND ENGINE (Python)                 │
│  ┌───────────────────────┐       ┌───────────────────────┐  │
│  │  Detection Engine     │       │  Attack Graph Engine  │  │
│  │  (Autoencoder, RF, IF)│       │  (MITRE ATT&CK Map)   │  │
│  └───────────┬───────────┘       └───────────┬───────────┘  │
│              │                               │              │
│  ┌───────────▼───────────┐       ┌───────────▼───────────┐  │
│  │  SOAR Playbook Engine │       │  Threat Intelligence  │  │
│  │  (IP Quarantine, Host)│       │  (IOC & CVE DB)       │  │
│  └───────────────────────┘       └───────────────────────┘  │
└──────────────────────────────┬──────────────────────────────┘
                               │ Scapy ARP Probes & Logs
┌──────────────────────────────▼──────────────────────────────┐
│                    NETWORK TELEMETRY AGENTS                 │
│   [ Network Scanner ]  [ Syslog ]  [ Zeek ]  [ Suricata ]   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### 1. Requirements
- Python 3.9+
- Linux, macOS, or Windows

### 2. Installation
```bash
git clone https://github.com/rksanjayvsbec/blackchain.git
cd blackchain
pip install -r requirements.txt
```

### 3. Launching NetShield AI
- **macOS / Linux:**
  ```bash
  chmod +x start_netshield.command
  ./start_netshield.command
  ```
- **Windows:**
  Double-click `start_netshield.bat` or run:
  ```cmd
  start_netshield.bat
  ```
- **Manual Start:**
  ```bash
  python3 backend/api_server.py
  ```
  Open `http://localhost:8000` in your web browser.

---

## 📡 API Endpoints

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/network-scan` | `GET` | Returns list of discovered active subnet hosts, vendor MACs, and status. |
| `/api/system-telemetry` | `GET` | Streams network bandwidth throughput, CPU/Memory telemetry, and active alerts. |
| `/api/active-sockets` | `GET` | Lists local listening ports, established connections, and PID owners. |
| `/api/block-ip` | `POST` | Quarantines an IP address via host-level firewall rules. |
| `/api/unblock-ip` | `POST` | Releases an IP address from quarantine. |

---

## 📄 License
MIT License. Developed for enterprise network defense and security operations automation.
