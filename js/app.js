/**
 * NetShield AI - Main Application Controller (Enhanced)
 */

class NetShieldApp {
  constructor() {
    this.currentScenario = "SSH Brute Force";
      // Devices will be loaded dynamically from the backend scanner
      this.devices = [];
      this.fetchConnectedDevices();

    this.activeAlerts = [
      {
        id: "ALT-9412",
        timestamp: new Date().toLocaleTimeString(),
        device_name: "Web Server-02",
        device_ip: "10.0.0.5",
        attack_category: "SSH Brute Force",
        confidence_score: 0.97,
        risk_score: 96.0,
        severity: "Critical",
        mitre_technique_id: "T1110",
        mitre_technique_name: "Brute Force",
        xai_reasons: [
          "✓ 412 Failed SSH Login Attempts within 60s",
          "✓ Outbound connection to known C2 IP 185.220.101.5 (LockBit Ransomware)",
          "✓ Outbound traffic burst of 2.3 GB",
          "✓ High entropy DNS subdomain queries"
        ]
      }
    ];

    this.chart = new window.TelemetryChart('telemetryCanvas');
    this.graph = new window.AttackGraphRenderer('attackGraphSvg');
    this.xaiModal = new window.XAIModalController();
    this.soar = new window.SOARUIController();
    this.chatbot = new window.SecurityCopilotChatbot();

    this.initEventListeners();
    this.renderAssetTable();
    this.renderAlertTimeline();
    this.renderActiveSockets();

    // Start Telemetry, Network Scan & Socket Inspector Auto-Refresh Loops
    setInterval(() => this.telemetryTick(), 2000);
    setInterval(() => this.fetchConnectedDevices(), 5000);
    setInterval(() => this.renderActiveSockets(), 5000);
  }

  async fetchConnectedDevices() {
    try {
      const response = await fetch('/api/network-scan');
      if (response.ok) {
        const data = await response.json();
        
        const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
        const customNames = JSON.parse(localStorage.getItem('custom_device_names') || '{}');
        
        // 1. Process active scanned devices
        this.devices = data.map(d => {
          const isBlocked = blockedIPs.includes(d.ip);
          const alias = customNames[d.ip] || customNames[d.mac];
          const displayType = alias || d.type;
          
          let defaultName = d.type;
          if (d.id === 'my_laptop') defaultName = "My System";
          else if (d.type === 'Network Asset') defaultName = "Connected Device";

          return {
            id: d.id,
            name: alias ? alias : defaultName,
            ip_address: d.ip,
            mac_address: d.mac,
            device_type: displayType,
            current_risk_score: isBlocked ? 0 : (d.risk !== undefined ? d.risk : 5),
            predicted_risk_24h: isBlocked ? 0 : (d.predicted_24h !== undefined ? d.predicted_24h : 10),
            status: isBlocked ? "Isolated" : d.status,
            threats: (d.status === "Suspicious" && !isBlocked) ? 1 : 0
          };
        });

        // 2. Rule 1: Ensure BLOCKED devices remain on the map as GREY nodes (Isolated) even when disconnected
        const scannedIPs = data.map(d => d.ip);
        blockedIPs.forEach(bIp => {
          if (!scannedIPs.includes(bIp) && bIp !== 'Localhost (You)') {
            const alias = customNames[bIp];
            this.devices.push({
              id: "blocked_" + bIp.replace(/\./g, '_'),
              name: alias ? alias : ("Blocked Device (" + bIp + ")"),
              ip_address: bIp,
              mac_address: "N/A",
              device_type: alias || "Blocked Device",
              current_risk_score: 0,
              predicted_risk_24h: 0,
              status: "Isolated", // Renders in GREY on the map!
              threats: 0
            });
          }
        });

        // Rule 2: Unblocked disconnected devices are NOT in data and NOT in blockedIPs, so they vanish completely!

        // Ensure "Localhost" gets a nicer name
        const laptop = this.devices.find(d => d.id === 'my_laptop');
        if (laptop && !customNames['my_laptop'] && !customNames['Localhost (You)']) {
          laptop.name = "My System";
        }
        
        this.renderAssetTable();
        this.updateHUDMetrics();
        this.renderBlockedDevicesHistory();
        
        if (this.graph) {
          this.graph.renderRealDevices(this.devices);
        }
      }
    } catch (e) {
      this.updateHUDMetrics();
      this.renderBlockedDevicesHistory();
    }
  }

  renderBlockedDevicesHistory() {
    const listElem = document.getElementById('blockedDevicesList');
    if (!listElem) return;

    const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
    if (blockedIPs.length === 0) {
      listElem.innerHTML = `<div style="font-size:0.75rem; color:#9ca3af;">No devices currently blocked.</div>`;
      return;
    }

    const customNames = JSON.parse(localStorage.getItem('custom_device_names') || '{}');

    listElem.innerHTML = blockedIPs.map(ip => {
      const name = customNames[ip] || `Blocked Host (${ip})`;
      return `
        <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(239,68,68,0.1); border:1px solid rgba(239,68,68,0.3); padding:0.4rem 0.6rem; border-radius:4px;">
          <div>
            <div style="font-size:0.8rem; font-weight:bold; color:#fff;">🚫 ${name}</div>
            <div style="font-size:0.7rem; color:#9ca3af; font-family:var(--font-mono);">${ip}</div>
          </div>
          <button onclick="window.NetShieldApp.unblockDevice('${ip}')" style="background:#10b981; color:#fff; border:none; padding:0.25rem 0.55rem; border-radius:4px; font-size:0.7rem; font-weight:bold; cursor:pointer; box-shadow:0 0 6px rgba(16,185,129,0.4);">
            🔓 Unblock
          </button>
        </div>
      `;
    }).join('');
  }

