/**
 * NetShield AI - Security Copilot Chatbot Widget
 * Floating conversational AI interface for network compromise investigation.
 */

class SecurityCopilotChatbot {
  constructor() {
    this.btn = document.getElementById('chatWidgetBtn');
    this.drawer = document.getElementById('chatDrawer');
    this.closeBtn = document.getElementById('closeChatBtn');
    this.messagesContainer = document.getElementById('chatMessages');
    this.input = document.getElementById('chatInput');
    this.sendBtn = document.getElementById('chatSendBtn');

    if (!this.btn || !this.drawer) return;

    this.btn.addEventListener('click', () => this.toggleDrawer());
    this.closeBtn.addEventListener('click', () => this.toggleDrawer(false));
    this.sendBtn.addEventListener('click', () => this.handleSend());
    this.input.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') this.handleSend();
    });

    this.addBotMessage(
      "👋 Hello! I am **NetShield AI Security Copilot**.\n\n" +
      "Ask me anything about active network compromises, 24-hour threat forecasts, or MITRE ATT&CK techniques.\n\n" +
      "Try asking:\n" +
      "• *Why is Server-02 compromised?*\n" +
      "• *Show predicted 24h risk for Production DB-01*\n" +
      "• *What auto-response actions can I take?*"
    );
  }

  toggleDrawer(forceState) {
    if (forceState !== undefined) {
      this.drawer.classList.toggle('active', forceState);
    } else {
      this.drawer.classList.toggle('active');
    }
  }

  addUserMessage(text) {
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble chat-bubble-user';
    bubble.innerText = text;
    this.messagesContainer.appendChild(bubble);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  addBotMessage(markdownText) {
    const bubble = document.createElement('div');
    bubble.className = 'chat-bubble chat-bubble-bot';
    
    // Simple markdown formatting replacement
    let html = markdownText
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/\n/g, '<br/>');

    bubble.innerHTML = html;

    // Add quick action buttons if mitigation steps mentioned
    if (markdownText.includes("Recommended SOAR")) {
      const btnGroup = document.createElement('div');
      btnGroup.style.marginTop = '0.75rem';
      btnGroup.style.display = 'flex';
      btnGroup.style.gap = '0.5rem';
      btnGroup.style.flexWrap = 'wrap';

      btnGroup.innerHTML = `
        <button onclick="window.NetShieldApp.executeSOARAction('Block IP', '185.220.101.5')" style="background:#ef4444; color:#fff; border:none; padding:0.35rem 0.65rem; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:bold;">Block IP 185.220.101.5</button>
        <button onclick="window.NetShieldApp.executeSOARAction('Isolate Host', '10.0.0.5')" style="background:#f59e0b; color:#000; border:none; padding:0.35rem 0.65rem; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:bold;">Isolate Web Server-02</button>
        <button onclick="window.NetShieldApp.generateReport('Web Server-02', '10.0.0.5')" style="background:#00f2fe; color:#000; border:none; padding:0.35rem 0.65rem; border-radius:4px; font-size:0.75rem; cursor:pointer; font-weight:bold;">Generate Incident PDF</button>
      `;
      bubble.appendChild(btnGroup);
    }

    this.messagesContainer.appendChild(bubble);
    this.messagesContainer.scrollTop = this.messagesContainer.scrollHeight;
  }

  handleSend() {
    const query = this.input.value.trim();
    if (!query) return;

    this.addUserMessage(query);
    this.input.value = '';

    // Simulate AI response delay
    setTimeout(() => {
      const q = query.toLowerCase();
      if (q.includes("why") || q.includes("server") || q.includes("compromised")) {
        this.addBotMessage(
          "Analysis for **Web Server-02** (10.0.0.5):\n\n" +
          "• Current Risk Score: **96%** (Predicted 24h: **97%**)\n" +
          "• AI Confidence Level: **97%**\n" +
          "• MITRE ATT&CK Mapping: **T1110 (Brute Force)**\n\n" +
          "**Key Threat Indicators Identified:**\n" +
          "✓ 412 Failed SSH Login Attempts within 60s\n" +
          "✓ Outbound Connection to Malicious C2 IP (185.220.101.5)\n" +
          "✓ Unusual Outbound Traffic Burst (2.3 GB)\n" +
          "✓ High Entropy DNS Requests to Suspicious Domain\n\n" +
          "**Recommended SOAR Mitigation Actions:**"
        );
      } else if (q.includes("predict") || q.includes("forecast") || q.includes("db") || q.includes("database")) {
        this.addBotMessage(
          "🔮 **Threat Prediction AI Analysis for Production DB-01** (10.0.0.12):\n\n" +
          "• Current Risk: **78%** ➔ **Predicted 24h Risk: 88%** (High Acceleration)\n" +
          "• Risk Velocity Factor: +10% increase over baseline\n" +
          "• Contributing Cause: Lateral MySQL port probe originating from compromised Web Server-02.\n\n" +
          "**Actionable Advice:** Isolate Web Server-02 immediately to prevent lateral breach."
        );
      } else if (q.includes("mitre") || q.includes("t1110") || q.includes("brute")) {
        this.addBotMessage(
          "📊 **MITRE ATT&CK Technique: T1110 - Brute Force**\n\n" +
          "• **Tactic:** Credential Access\n" +
          "• **Description:** Adversaries systematically guess passwords to compromise credentials.\n\n" +
          "**NetShield AI Hardening Recommendations:**\n" +
          "✓ Enable Multi-Factor Authentication (MFA)\n" +
          "✓ Implement Strict Account Lockout (3 failed attempts)\n" +
          "✓ Rate-limit SSH login velocity"
        );
      } else {
        this.addBotMessage(
          "NetShield AI Copilot is actively monitoring **5 network devices**.\n\n" +
          "Active Alerts: **1 Critical SSH Brute Force Attack detected on Web Server-02**.\n" +
          "Top Threat Origin: **IP 185.220.101.5 (Russia - LockBit Ransomware C2)**.\n\n" +
          "What specific device or threat would you like me to analyze?"
        );
      }
    }, 400);
  }
}

window.SecurityCopilotChatbot = SecurityCopilotChatbot;
