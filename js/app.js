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

  async unblockDevice(ip) {
    try {
      await fetch('/api/unblock-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      });
    } catch(e) {
      console.error("Failed to execute system unblock", e);
    }

    // Remove from localStorage
    let blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
    blockedIPs = blockedIPs.filter(x => x !== ip);
    localStorage.setItem('blocked_ips', JSON.stringify(blockedIPs));

    // Reset status in local memory if present
    const dev = this.devices.find(d => d.ip_address === ip);
    if (dev) {
      dev.status = "Safe";
      dev.current_risk_score = 5;
      dev.predicted_risk_24h = 10;
    }

    // Show toast notification
    if (this.soar) {
      this.soar.showNotification(`Device ${ip} unblocked and re-enabled on network!`, "success");
    }

    // Give OS ARP flush & ping re-discovery 1000ms to complete before fetching
    setTimeout(() => {
      this.fetchConnectedDevices();
    }, 1000);
  }

  async clearBlockedHistory() {
    const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
    for (const ip of blockedIPs) {
      try {
        await fetch('/api/unblock-ip', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip: ip })
        });
      } catch(e) {}
    }
    localStorage.removeItem('blocked_ips');
    if (this.soar) {
      this.soar.showNotification("Cleared all blocked device history!", "success");
    }
    setTimeout(() => {
      this.fetchConnectedDevices();
    }, 1000);
  }

  updateHUDMetrics() {
    // 1. Calculate Active Threats from real devices
    const activeThreats = this.devices.filter(d => d.status === 'Suspicious' || d.status === 'Compromised').length;
    
    // 2. System Threat Status
    const statusElem = document.getElementById('hudThreatStatus');
    const iconElem = document.getElementById('hudThreatIcon');
    if (statusElem) {
      if (activeThreats > 0) {
        statusElem.innerText = "CRITICAL";
        statusElem.style.color = "#ef4444";
        if (iconElem) {
          iconElem.style.background = "rgba(239, 68, 68, 0.15)";
          iconElem.style.color = "#ef4444";
          iconElem.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
        }
      } else {
        statusElem.innerText = "HEALTHY";
        statusElem.style.color = "#10b981";
        if (iconElem) {
          iconElem.style.background = "rgba(16, 185, 129, 0.15)";
          iconElem.style.color = "#10b981";
          iconElem.innerHTML = '<i class="fa-solid fa-shield-halved"></i>';
        }
      }
    }

    // 3. Top High-Risk Asset
    const topRiskElem = document.getElementById('hudTopRiskAsset');
    if (topRiskElem) {
      if (this.devices.length > 0) {
        const sorted = [...this.devices].sort((a, b) => b.current_risk_score - a.current_risk_score);
        const topDev = sorted[0];
        if (topDev && topDev.current_risk_score > 20) {
          topRiskElem.innerText = topDev.name || topDev.ip_address;
          topRiskElem.style.color = topDev.current_risk_score > 70 ? "#ef4444" : "#f59e0b";
        } else {
          topRiskElem.innerText = "None (All Safe)";
          topRiskElem.style.color = "#10b981";
        }
      } else {
        topRiskElem.innerText = "None (All Safe)";
        topRiskElem.style.color = "#10b981";
      }
    }

    // 4. Active Threat Alerts Count
    const alertCountElem = document.getElementById('hudAlertCount');
    if (alertCountElem) {
      alertCountElem.innerText = activeThreats;
      alertCountElem.style.color = activeThreats > 0 ? "#ef4444" : "#10b981";
    }

    // 5. Total Connected Devices HUD & Header Badges
    const devCount = this.devices ? this.devices.length : 0;
    const hudDevicesElem = document.getElementById('hudConnectedDevices');
    if (hudDevicesElem) {
      hudDevicesElem.innerText = `${devCount} Connected`;
    }
    const topBadgeElem = document.getElementById('topologyDeviceCountBadge');
    if (topBadgeElem) {
      topBadgeElem.innerText = `${devCount} Devices Online`;
    }
    const scoreBadgeElem = document.getElementById('scoreboardDeviceCountBadge');
    if (scoreBadgeElem) {
      scoreBadgeElem.innerText = `${devCount} Assets Monitored`;
    }
  }

  initEventListeners() {
    const buttons = document.querySelectorAll('.scenario-btn');
    buttons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        buttons.forEach(b => b.classList.remove('active'));
        e.target.classList.add('active');
        this.currentScenario = e.target.dataset.scenario;
        this.soar.showNotification(`Switched Telemetry Scenario to: [${this.currentScenario}]`);
      });
    });
  }

  async telemetryTick() {
    let throughput = 0;
    let threats = this.activeAlerts.length;

    try {
      const res = await fetch('/api/system-telemetry');
      if (res.ok) {
        const data = await res.json();
        throughput = data.throughput_kbps;
      }
    } catch(e) {
      // Fallback
    }

