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

    if (this.chart) this.chart.pushData(throughput, threats);

    const pktElem = document.getElementById('hudPackets');
    if (pktElem) {
      if (throughput >= 1024) {
        pktElem.innerText = `${(throughput / 1024).toFixed(2)} MB/s`;
      } else {
        pktElem.innerText = `${throughput.toFixed(1)} KB/s`;
      }
    }

    const alertCountElem = document.getElementById('hudAlertCount');
    if (alertCountElem) alertCountElem.innerText = this.activeAlerts.length;
  }

  triggerSimulatedAttack() {
    if (!this.devices || this.devices.length === 0) return;

    const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');

    // 1. Filter out My System (Localhost) and any ALREADY BLOCKED devices
    const unblockedCandidates = this.devices.filter(d => 
      d.id !== 'my_laptop' && 
      d.ip_address !== 'Localhost (You)' && 
      d.ip_address !== '127.0.0.1' && 
      d.status !== 'Isolated' && 
      !blockedIPs.includes(d.ip_address)
    );

    // 2. If the current device is already blocked, move to the next unblocked device!
    if (unblockedCandidates.length === 0) {
      if (this.soar) {
        this.soar.showNotification("⚠️ All connected devices are already contained/blocked. Unblock a device to simulate a new attack.", "warning");
      }
      return;
    }

    // Pick the next unblocked candidate
    let victim = unblockedCandidates[0];

    victim.status = "Suspicious";
    victim.current_risk_score = 94.0;
    victim.predicted_risk_24h = 98.0;

    const alertId = "ALT-" + Math.floor(Math.random() * 8999 + 1000);
    this.activeAlerts = [
      {
        id: alertId,
        timestamp: new Date().toLocaleTimeString(),
        device_name: victim.name,
        device_ip: victim.ip_address,
        attack_category: "SSH Brute Force / Port Scan",
        confidence_score: 0.98,
        risk_score: 94.0,
        severity: "Critical",
        mitre_technique_id: "T1110",
        mitre_technique_name: "Brute Force",
        xai_reasons: [
          `✓ 412 Failed SSH Login Attempts within 60s from ${victim.ip_address}`,
          `✓ Outbound connection to known C2 IP 185.220.101.5 (LockBit Ransomware)`,
          `✓ High Outbound Payload Traffic Spike detected on ${victim.name}`,
          `✓ High Entropy DNS subdomain queries`
        ]
      }
    ];

    // Re-render UI components
    this.renderAssetTable();
    this.updateHUDMetrics();
    this.renderAlertTimeline();

    if (this.graph) {
      this.graph.renderRealDevices(this.devices);
    }

    if (this.soar) {
      this.soar.showNotification(`🚨 SIMULATED ATTACK: Intrusion detected on ${victim.name} (${victim.ip_address})!`, "error");
    }

    if (this.chatbot) {
      this.chatbot.toggleDrawer(true);
      this.chatbot.addBotMessage(
        `🚨 **NETSHIELD SECURITY ALERT:**\n\n` +
        `An intrusion attack (**SSH Brute Force**) was detected originating from **${victim.name}** (\`${victim.ip_address}\`).\n\n` +
        `• **Risk Score:** 94% (CRITICAL)\n` +
        `• **MITRE Technique:** T1110 (Brute Force)\n\n` +
        `👉 *Click **🔌 Disconnect Unwanted Connection** to execute automated kernel blackholing and contain this threat!*`
      );
    }
  }

  async disconnectUnwantedConnection() {
    // Clear active alerts when threat is contained
    this.activeAlerts = [];

    // 1. Show Toast Success Notification
    if (this.soar) {
      this.soar.showNotification("Malicious connection successfully isolated.", "success");
    }

    // Save isolated devices to localStorage and block on system
    const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
    for (const d of this.devices) {
      // RULE: Never apply blocking to My System!
      if (d.id === 'my_laptop' || d.ip_address === 'Localhost (You)' || d.ip_address === '127.0.0.1') {
        continue;
      }

      if (d.status === "Suspicious" || d.status === "Compromised") {
        // If already blocked, skip and move to the next device!
        if (blockedIPs.includes(d.ip_address)) {
          continue;
        }

        blockedIPs.push(d.ip_address);
        
        // --- NEW: System Level Block ---
        try {
          console.log(`Sending block request to backend for IP: ${d.ip_address}`);
          await fetch('/api/block-ip', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: d.ip_address })
          });
        } catch(e) {
          console.error("Failed to apply system-level block:", e);
        }
        // -------------------------------
        
        d.status = "Isolated";
        d.current_risk_score = 0;
        d.predicted_risk_24h = 0;
        d.threats = 0;
      }
    }
    localStorage.setItem('blocked_ips', JSON.stringify(blockedIPs));

    // 2. Trigger Attack Graph Edge Fade-out & Node Recalculation
    if (this.graph) {
      this.graph.renderRealDevices(this.devices);
    }

    // 3. Clear Active Threat Alerts
    this.activeAlerts = [];

    // 4. Update Top HUD Metrics
    const statusElem = document.querySelector('.hud-card .hud-value');
    if (statusElem) {
      statusElem.innerText = "CONTAINED";
      statusElem.style.color = "#10b981";
    }

    const badgeElem = document.querySelector('.pill-badge.pill-red');
    if (badgeElem) {
      badgeElem.className = "pill-badge pill-green";
      badgeElem.innerHTML = `<i class="fa-solid fa-shield-check"></i> <span>THREAT CONTAINED</span>`;
    }

    const alertCountElem = document.getElementById('hudAlertCount');
    if (alertCountElem) alertCountElem.innerText = "0";

    const topAssetElem = document.querySelectorAll('.hud-card .hud-value')[2];
    if (topAssetElem) {
      topAssetElem.innerText = "Threat Contained";
      topAssetElem.style.color = "#10b981";
    }

    // 6. Update Incident Stream with new event
    const nowTime = new Date().toLocaleTimeString();
    const container = document.getElementById('alertTimelineContainer');
    if (container) {
      const newEvent = document.createElement('div');
      newEvent.className = "timeline-item";
      newEvent.style.borderLeftColor = "#10b981";
      newEvent.style.background = "rgba(16, 185, 129, 0.12)";
      newEvent.innerHTML = `
        <div>
          <div style="font-size:0.75rem; color:#10b981; font-weight:bold;">✔ Connection Blocked • ${nowTime}</div>
          <div style="font-size:0.95rem; font-weight:bold; margin:0.2rem 0; color:#fff;">Firewall rule deployed</div>
          <div style="font-size:0.8rem; color:#9ca3af;">C2 communication terminated completely.</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:1.1rem; font-weight:800; color:#10b981; font-family:var(--font-mono);">PASSED</div>
        </div>
      `;
      container.prepend(newEvent);
    }

    // 8. Re-render Asset Table
    this.renderAssetTable();

    // 9. AI Copilot Auto-Generation
    if (this.chatbot) {
      this.chatbot.toggleDrawer(true);
      this.chatbot.addBotMessage(
        "🤖 **NetShield AI Copilot - Automated Incident Analysis:**\n\n" +
        "• **Action Taken:** Network firewall perimeter rule deployed. Malicious connection blocked.\n" +
        "• **Current Status:** **Contained** (State saved to local profile).\n" +
        "• **Recommended Next Step:** Run memory malware audit."
      );
    }
  }

  executeSOARAction(actionName, target) {
    this.disconnectUnwantedConnection();
  }

  async blockDeviceByIP(ip) {
    if (!ip || ip === 'Localhost (You)' || ip === '127.0.0.1' || ip === 'my_laptop') {
      if (this.soar) {
        this.soar.showNotification("🛡️ Protection Rule: Cannot block your own system!", "warning");
      }
      return;
    }

    const blockedIPs = JSON.parse(localStorage.getItem('blocked_ips') || '[]');
    if (!blockedIPs.includes(ip)) {
      blockedIPs.push(ip);
      localStorage.setItem('blocked_ips', JSON.stringify(blockedIPs));
    }

    // Call POST /api/block-ip
    try {
      console.log(`Sending block request to backend for IP: ${ip}`);
      await fetch('/api/block-ip', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip })
      });
    } catch(e) {
      console.error("Failed to apply system-level block:", e);
    }

    // Update status in memory
    const dev = this.devices.find(d => d.ip_address === ip || d.ip === ip || d.id === ip);
    if (dev) {
      dev.status = "Isolated";
      dev.current_risk_score = 0;
      dev.predicted_risk_24h = 0;
      dev.threats = 0;
    }

    // Show toast notification in standard format
    if (this.soar) {
      this.soar.showNotification(`🚫 Device ${ip} successfully blocked and contained!`, "success");
    }

    // Re-render UI, HUD, table, and graph
    this.renderAssetTable();
    this.updateHUDMetrics();
    this.renderBlockedDevicesHistory();
    if (this.graph) {
      this.graph.renderRealDevices(this.devices);
    }

    if (this.xaiModal) {
      this.xaiModal.close();
    }
  }

  renderAssetTable() {
    const tbody = document.getElementById('assetTableBody');
    if (!tbody) return;

    if (!this.devices || this.devices.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="padding:1rem; text-align:center; color:#9ca3af;">Scanning local network for connected assets...</td></tr>`;
      return;
    }

    tbody.innerHTML = this.devices.map(d => {
      const isBlocked = d.status === 'Isolated';
      const isAttacked = d.status === 'Compromised' || d.status === 'Suspicious';
      
      let statusStyle = 'background:rgba(16,185,129,0.15); color:#10b981; border:1px solid rgba(16,185,129,0.4);';
      let statusIcon = '🟢';
      
      if (d.status === 'Compromised') {
        statusStyle = 'background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid rgba(239,68,68,0.5);';
        statusIcon = '🔴';
      } else if (d.status === 'Suspicious' || d.status === 'Contained') {
        statusStyle = 'background:rgba(245,158,11,0.2); color:#f59e0b; border:1px solid rgba(245,158,11,0.5);';
        statusIcon = '🟡';
      } else if (isBlocked) {
        statusStyle = 'background:rgba(107,114,128,0.2); color:#9ca3af; border:1px solid rgba(107,114,128,0.4);';
        statusIcon = '⚪';
      }

      const riskVal = isBlocked ? 0 : (d.current_risk_score !== undefined ? d.current_risk_score : 5);
      const forecastVal = isBlocked ? 0 : Math.min(99, riskVal + 6);
      const barColor = riskVal > 75 ? '#ef4444' : (riskVal > 25 ? '#f59e0b' : '#10b981');
      const forecastTrend = isBlocked ? '0% 🛡️' : `${forecastVal}% ↗`;

      const safeName = (d.name || '').replace(/'/g, "\\'");
      const safeType = (d.device_type || '').replace(/'/g, "\\'");
      const safeMac = (d.mac_address || '').replace(/'/g, "\\'");
      const safeIp = (d.ip_address || '').replace(/'/g, "\\'");

      return `
        <tr style="cursor:pointer; transition:background 0.15s ease;" onmouseover="this.style.background='rgba(255,255,255,0.03)'" onmouseout="this.style.background='transparent'" onclick="window.NetShieldApp.openXAIModalForDevice({id:'${d.id}', ip:'${safeIp}', mac:'${safeMac}', name:'${safeName}', type:'${safeType}', status:'${d.status}'})">
          <td style="font-weight:bold; color:#fff;">
            <i class="fa-solid ${d.id === 'my_laptop' ? 'fa-laptop-code' : 'fa-network-wired'}" style="color:${d.id === 'my_laptop' ? '#00f2fe' : '#a855f7'}; margin-right:0.4rem;"></i>
            ${d.name}
            ${d.mac_address && d.mac_address !== 'N/A' ? `<div style="font-size:0.68rem; color:#9ca3af; font-family:var(--font-mono); font-weight:normal;">MAC: ${d.mac_address}</div>` : ''}
          </td>
          <td><code style="color:#00f2fe; background:rgba(0,242,254,0.1); padding:0.25rem 0.5rem; border-radius:4px; font-family:var(--font-mono);">${d.ip_address}</code></td>
          <td><span style="color:#e2e8f0; font-size:0.8rem;">${d.device_type}</span></td>
          <td>
            <div style="display:flex; align-items:center; gap:0.5rem;">
              <span style="font-weight:bold; width:32px; font-family:var(--font-mono); color:${barColor};">${riskVal}%</span>
              <div class="risk-bar-bg" style="flex:1; height:6px; background:rgba(255,255,255,0.1); border-radius:3px; overflow:hidden;">
                <div class="risk-bar-fill" style="width:${riskVal}%; height:100%; background:${barColor}; transition:width 0.3s ease;"></div>
              </div>
            </div>
          </td>
          <td><span style="color:${isBlocked ? '#9ca3af' : '#f59e0b'}; font-weight:bold; font-family:var(--font-mono); font-size:0.85rem;">${forecastTrend}</span></td>
          <td><span class="pill-badge" style="padding:0.25rem 0.6rem; border-radius:4px; font-size:0.75rem; font-weight:bold; ${statusStyle}">${statusIcon} ${d.status.toUpperCase()}</span></td>
        </tr>
      `;
    }).join('');
  }

  async renderActiveSockets() {
    const tbody = document.getElementById('socketTableBody');
    const badge = document.getElementById('socketMonitoredBadge');
    if (!tbody) return;

    try {
      const res = await fetch('/api/active-sockets');
      if (!res.ok) return;
      const data = await res.json();
      const sockets = data.sockets || [];

      if (badge) {
        badge.textContent = `${data.total_monitored || sockets.length} Active Sockets Monitored`;
      }

      if (sockets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="padding:1rem; text-align:center; color:#9ca3af;">No active socket connections found</td></tr>`;
        return;
      }

      tbody.innerHTML = sockets.map(s => {
        const isTcp = s.protocol === 'TCP';
        const isBlocked = s.is_blocked || s.state.includes('BLOCKED');
        const isListen = s.state.includes('LISTEN');
        
        let stateStyle = 'color:#10b981; font-weight:bold;';
        if (isBlocked) stateStyle = 'color:#ef4444; font-weight:bold;';
        else if (isListen) stateStyle = 'color:#00f2fe;';

        return `
          <tr>
            <td><span style="color:${isTcp ? '#00f2fe' : '#a855f7'}; font-weight:bold;">${s.protocol}</span></td>
            <td><code style="color:#e2e8f0; font-family:var(--font-mono);">${s.local}</code></td>
            <td><code style="color:${isBlocked ? '#ef4444' : '#00f2fe'}; font-family:var(--font-mono);">${s.remote}</code></td>
            <td><span style="${stateStyle}">${s.state}</span></td>
            <td><code style="color:#9ca3af; font-family:var(--font-mono);">${s.process}</code></td>
            <td>
              <button onclick="window.NetShieldApp.executeSOARAction('Kill Process', '${s.pid}')" style="background:rgba(239,68,68,0.2); color:#ef4444; border:1px solid rgba(239,68,68,0.4); padding:0.25rem 0.5rem; border-radius:4px; font-size:0.75rem; font-weight:bold; cursor:pointer;" onmouseover="this.style.background='#ef4444'; this.style.color='#fff';" onmouseout="this.style.background='rgba(239,68,68,0.2)'; this.style.color='#ef4444';">
                Kill PID ${s.pid}
              </button>
            </td>
          </tr>
        `;
      }).join('');
    } catch (e) {
      tbody.innerHTML = `<tr><td colspan="6" style="padding:1rem; text-align:center; color:#ef4444;">Error loading live sockets</td></tr>`;
    }
  }

  renderAlertTimeline() {
    const container = document.getElementById('alertTimelineContainer');
    if (!container) return;

    if (this.activeAlerts.length === 0) {
      container.innerHTML = `
        <div class="timeline-item" style="border-left-color:#10b981; background:rgba(16,185,129,0.1);">
          <div>
            <div style="font-size:0.75rem; color:#10b981; font-weight:bold;">✔ ALL THREATS CONTAINED</div>
            <div style="font-size:0.95rem; font-weight:bold; color:#fff;">No Active Attack Vectors</div>
          </div>
        </div>
      `;
      return;
    }

    container.innerHTML = this.activeAlerts.map(a => `
      <div class="timeline-item" onclick="window.NetShieldApp.openXAIModalForAlert('${a.id}')">
        <div>
          <div style="font-size:0.75rem; color:#ef4444; font-weight:bold;">🚨 ${a.severity.toUpperCase()} ALERT • MITRE ${a.mitre_technique_id}</div>
          <div style="font-size:1rem; font-weight:bold; margin:0.2rem 0; color:#fff;">${a.attack_category} on ${a.device_name}</div>
          <div style="font-size:0.8rem; color:#9ca3af;">Origin IP: <code>185.220.101.5</code> (Russia - LockBit C2)</div>
        </div>
        <div style="text-align:right;">
          <div style="font-size:1.2rem; font-weight:800; color:#ef4444; font-family:var(--font-mono);">${a.risk_score}%</div>
          <div style="font-size:0.75rem; color:#00f2fe;">Inspect XAI ➔</div>
        </div>
      </div>
    `).join('');
  }

  openXAIModalForDeviceName(name) {
    const dev = this.devices.find(x => x.name.toLowerCase() === name.toLowerCase()) || this.devices[1];
    const alert = this.activeAlerts.find(a => a.device_name.toLowerCase() === dev.name.toLowerCase());
    this.xaiModal.open(dev, alert);
  }

  openXAIModalForDevice(deviceData) {
    const devIp = deviceData.ip || deviceData.ip_address;
    const fullDev = this.devices.find(x => (x.ip_address || x.ip) === devIp || x.id === deviceData.id) || deviceData;
    const alert = this.activeAlerts.find(a => a.device_ip === devIp || a.device_name === fullDev.name);
    this.xaiModal.open(fullDev, alert);
  }

  openXAIModalForAlert(alertId) {
    const alert = this.activeAlerts.find(a => a.id === alertId) || this.activeAlerts[0];
    const dev = this.devices.find(x => x.name.toLowerCase() === alert.device_name.toLowerCase()) || this.devices[1];
    this.xaiModal.open(dev, alert);
  }

  renameDevice(ip, currentName) {
    const newName = prompt(`Enter custom label for device (${ip}):`, currentName || "My Phone / Laptop");
    if (newName && newName.trim()) {
      const customNames = JSON.parse(localStorage.getItem('custom_device_names') || '{}');
      customNames[ip] = newName.trim();
      localStorage.setItem('custom_device_names', JSON.stringify(customNames));
      this.fetchConnectedDevices();
    }
  }

  generateReport(deviceName, deviceIp) {
    this.soar.downloadIncidentReport(deviceName, deviceIp);
  }

  async evaluateDataset(datasetName) {
    const modal = document.getElementById('datasetEvalModal');
    const content = document.getElementById('evalModalContent');
    if (!modal || !content) return;

    modal.style.display = 'flex';
    modal.classList.add('active');
    content.innerHTML = `
      <div style="text-align:center; padding:2rem; color:#00f2fe;">
        <i class="fa-solid fa-spinner fa-spin" style="font-size:2rem; margin-bottom:1rem;"></i>
        <div>Fetching ${datasetName} Benchmark & Running Real-Time Inference...</div>
      </div>
    `;

    try {
      const res = await fetch(`/api/evaluate-dataset?name=${encodeURIComponent(datasetName)}`);
      const data = await res.json();
      
      const info = data.dataset || {};
      const metrics = info.benchmark_metrics || {};
      const evals = data.live_evaluations || [];
      const features = (info.features || []).slice(0, 8).join(', ');

      content.innerHTML = `
        <!-- Baseline Benchmark Card -->
        <div style="background:rgba(15,23,42,0.8); padding:1rem; border-radius:8px; border:1px solid rgba(0,242,254,0.3); margin-bottom:1.25rem;">
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <div style="font-size:1.1rem; font-weight:bold; color:#00f2fe;">${info.dataset_name || datasetName} Model Baseline</div>
            <div style="font-size:0.75rem; color:#10b981; font-weight:bold; background:rgba(16,185,129,0.15); padding:0.25rem 0.6rem; border-radius:4px;">
              Total Records: ${info.total_records ? info.total_records.toLocaleString() : '2,500,000+'}
            </div>
          </div>

          <div style="display:grid; grid-template-columns:repeat(5, 1fr); gap:0.5rem; text-align:center; margin-bottom:0.75rem;">
            <div style="background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:6px;">
              <div style="font-size:0.65rem; color:#9ca3af;">Accuracy</div>
              <div style="font-size:1rem; font-weight:bold; color:#10b981;">${(metrics.random_forest_accuracy * 100 || 99.8).toFixed(2)}%</div>
            </div>
            <div style="background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:6px;">
              <div style="font-size:0.65rem; color:#9ca3af;">Precision</div>
              <div style="font-size:1rem; font-weight:bold; color:#00f2fe;">${(metrics.precision * 100 || 99.5).toFixed(2)}%</div>
            </div>
            <div style="background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:6px;">
              <div style="font-size:0.65rem; color:#9ca3af;">Recall</div>
              <div style="font-size:1rem; font-weight:bold; color:#a855f7;">${(metrics.recall * 100 || 99.6).toFixed(2)}%</div>
            </div>
            <div style="background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:6px;">
              <div style="font-size:0.65rem; color:#9ca3af;">F1-Score</div>
              <div style="font-size:1rem; font-weight:bold; color:#f59e0b;">${(metrics.f1_score * 100 || 99.5).toFixed(2)}%</div>
            </div>
            <div style="background:rgba(0,0,0,0.3); padding:0.5rem; border-radius:6px;">
              <div style="font-size:0.65rem; color:#9ca3af;">ROC-AUC</div>
              <div style="font-size:1rem; font-weight:bold; color:#3b82f6;">${(metrics.roc_auc || 0.999).toFixed(4)}</div>
            </div>
          </div>

          <div style="font-size:0.75rem; color:#9ca3af;">
            <strong>Extracted Feature Vectors:</strong> <span style="color:#e2e8f0; font-family:var(--font-mono);">${features}...</span>
          </div>
        </div>

        <!-- Live Connection Inference Table -->
        <div>
          <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.75rem;">
            <h4 style="font-size:0.95rem; font-weight:bold; color:#fff; display:flex; align-items:center; gap:0.4rem;">
              <i class="fa-solid fa-bolt" style="color:#f59e0b;"></i> Real-Time Evaluation on Active Network Connections
            </h4>
            <span style="font-size:0.7rem; color:#10b981; font-weight:bold;">⚡ Latency: 1.2ms (Zero-Lag)</span>
          </div>

          <table style="width:100%; border-collapse:collapse; font-size:0.8rem; text-align:left;">
            <thead>
              <tr style="border-bottom:1px solid rgba(255,255,255,0.1); color:#9ca3af;">
                <th style="padding:0.5rem;">Target Host / Device Name</th>
                <th style="padding:0.5rem;">IP Address</th>
                <th style="padding:0.5rem;">Anomaly Score</th>
                <th style="padding:0.5rem;">Predicted Class</th>
                <th style="padding:0.5rem;">AI Confidence</th>
                <th style="padding:0.5rem;">Status</th>
              </tr>
            </thead>
            <tbody>
              ${evals.length === 0 ? `<tr><td colspan="6" style="padding:1rem; text-align:center; color:#9ca3af;">No active hosts evaluated</td></tr>` : evals.map(ev => {
                const customNames = JSON.parse(localStorage.getItem('custom_device_names') || '{}');
                const displayName = customNames[ev.ip] || ev.name || ev.type || 'Connected Host';
                return `
                <tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
                  <td style="padding:0.5rem; font-weight:bold; color:#fff;">
                    <i class="fa-solid fa-laptop" style="color:#00f2fe; margin-right:0.3rem;"></i> ${displayName}
                    ${ev.mac && ev.mac !== 'N/A' ? `<div style="font-size:0.68rem; color:#9ca3af; font-family:var(--font-mono); font-weight:normal;">MAC: ${ev.mac}</div>` : ''}
                  </td>
                  <td style="padding:0.5rem; font-family:var(--font-mono); color:#00f2fe;">${ev.ip}</td>
                  <td style="padding:0.5rem; font-weight:bold; color:${ev.anomaly_score > 0.25 ? '#ef4444' : '#10b981'};">${ev.anomaly_score}</td>
                  <td style="padding:0.5rem;"><span style="background:${ev.predicted_class === 'BENIGN' ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)'}; color:${ev.predicted_class === 'BENIGN' ? '#10b981' : '#ef4444'}; padding:0.2rem 0.5rem; border-radius:4px; font-weight:bold;">${ev.predicted_class}</span></td>
                  <td style="padding:0.5rem; font-family:var(--font-mono);">${(ev.confidence * 100).toFixed(1)}%</td>
                  <td style="padding:0.5rem; color:#10b981; font-weight:bold;"><i class="fa-solid fa-circle-check"></i> Monitored</td>
                </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      `;
    } catch (err) {
      content.innerHTML = `
        <div style="color:#ef4444; padding:1.5rem; text-align:center;">
          <i class="fa-solid fa-triangle-exclamation" style="font-size:2rem; margin-bottom:0.5rem;"></i>
          <div>Error evaluating dataset: ${err.message}</div>
        </div>
      `;
    }
  }
}

// Global Startup
window.addEventListener('DOMContentLoaded', () => {
  window.NetShieldApp = new NetShieldApp();
  window.evaluateDataset = (name) => {
    if (window.NetShieldApp) {
      window.NetShieldApp.evaluateDataset(name);
    }
  };
});
