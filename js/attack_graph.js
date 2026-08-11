/**
 * NetShield AI - Attack Graph Visualization Module (Enhanced)
 * Supports dynamic edge fade-out removal, node state recalculation, and animated topology updates.
 */

class AttackGraphRenderer {
  constructor(svgId) {
    this.svg = document.getElementById(svgId);
    if (!this.svg) return;
    
    // Set responsive viewBox to a taller size to prevent clipping
    this.svg.setAttribute("viewBox", "0 0 800 500");
    this.svg.style.width = "100%";
    this.svg.style.height = "100%";

    this.nodes = [];
    this.edges = [];
    
    this.draggedNode = null;
    this.setupDragEvents();

    this.render();
  }

  setupDragEvents() {
    this.svg.addEventListener('mousemove', (e) => {
      if (!this.draggedNode) return;
      
      const pt = this.svg.createSVGPoint();
      pt.x = e.clientX;
      pt.y = e.clientY;
      const svgP = pt.matrixTransform(this.svg.getScreenCTM().inverse());
      
      // Add boundaries so it can't be dragged outside the viewBox
      this.draggedNode.x = Math.max(30, Math.min(770, svgP.x));
      this.draggedNode.y = Math.max(30, Math.min(470, svgP.y));
      
      this.render(); // Re-render to update edges and nodes
    });

    this.svg.addEventListener('mouseup', () => {
      this.draggedNode = null;
    });
    
    this.svg.addEventListener('mouseleave', () => {
      this.draggedNode = null;
    });
  }

  renderRealDevices(realDevices) {
    // Preserve existing node positions if they exist
    const existingPositions = {};
    this.nodes.forEach(n => {
      existingPositions[n.id] = { x: n.x, y: n.y };
    });

    this.nodes = [];
    this.edges = [];
    
    // 1. Find the most common subnet among the devices
    const subnetCounts = {};
    realDevices.forEach(d => {
      const ip = d.ip_address || d.ip || "";
      const match = ip.match(/^(\d+\.\d+\.\d+)\./);
      if (match) {
        const sub = match[1];
        subnetCounts[sub] = (subnetCounts[sub] || 0) + 1;
      }
    });
    
    let primarySubnet = null;
    let maxCount = 0;
    for (const [sub, count] of Object.entries(subnetCounts)) {
      if (count > maxCount) {
        maxCount = count;
        primarySubnet = sub;
      }
    }

    // 2. Find the Hotspot Node to act as the center
    let centerNode = realDevices.find(d => {
      const type = d.device_type || d.type || "";
      const ip = d.ip_address || d.ip || "";
      return type === 'VSBEC Hotspot' || ip.endsWith('.1');
    });
    
    // Fallback: If no hotspot found, use 'my_laptop' as center
    if (!centerNode) {
      centerNode = realDevices.find(d => d.id === 'my_laptop');
    }
    
    // Ensure we have a center node
    if (!centerNode) {
      centerNode = { id: "my_laptop", label: "My System", type: "Workstation", status: "Safe", risk: 5, ip: "Localhost" };
      realDevices.push(centerNode);
    }

    // 3. Circular Layout Positioning
    // VSBEC Hotspot in the center
    const centerId = centerNode.id;
    const cx = existingPositions[centerId] ? existingPositions[centerId].x : 400;
    const cy = existingPositions[centerId] ? existingPositions[centerId].y : 250;
    
    // Add center node to graph
    this.nodes.push({ 
      id: centerId, 
      label: centerNode.ip_address || centerNode.ip || centerNode.label, 
      name: centerNode.name,
      type: centerNode.device_type || centerNode.type, 
      x: cx, 
      y: cy, 
      status: centerNode.status, 
      risk: centerNode.current_risk_score !== undefined ? centerNode.current_risk_score : centerNode.risk, 
      ip: centerNode.ip_address || centerNode.ip 
    });

    // 4. Distribute all other devices in a circle around the center
    const otherDevices = realDevices.filter(d => d.id !== centerId);
    const radius = 170; // Stay within 500px height
    
    otherDevices.forEach((device, index) => {
      // Calculate distinct circular position for every node so they never overlap
      const angle = (index / otherDevices.length) * 2 * Math.PI;
      const x = cx + radius * Math.cos(angle);
      const y = cy + radius * Math.sin(angle);
      
      this.nodes.push({
        id: device.id,
        label: device.ip_address || device.ip || (device.id === 'my_laptop' ? 'My System' : device.id),
        name: device.name,
        type: device.device_type || device.type,
        x: x,
        y: y,
        status: device.status,
        risk: device.current_risk_score !== undefined ? device.current_risk_score : device.risk,
        ip: device.ip_address || device.ip || 'Localhost'
      });
      
      // Connect to center (Hotspot -> Device)
      this.edges.push({
        id: `e_${device.id}`,
        source: centerId,
        target: device.id,
        status: device.status === "Suspicious" ? "AttackPath" : (device.status === "Isolated" ? "Isolated" : "Normal"),
        label: device.id === "my_laptop" ? "WLAN (You)" : (device.status === "Isolated" ? "Blocked" : "WLAN")
      });
    });

    this.render();
  }

  disconnectUnwantedConnection() {
    const attackEdgeElements = this.svg.querySelectorAll('.edge-attack');
    attackEdgeElements.forEach(el => {
      el.style.transition = "opacity 0.4s ease-out, stroke-width 0.4s ease-out";
      el.style.opacity = "0";
    });

    setTimeout(() => {
      this.edges = this.edges.filter(e => e.status !== "AttackPath");
      this.render();
    }, 450);
  }

  render() {
    if (!this.svg) return;
    this.svg.innerHTML = '';

    // Define SVG Filters & Markers
    this.svg.innerHTML += `
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#00f2fe" />
        </marker>
        <marker id="arrow-red" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
        </marker>
        <filter id="glow-red">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
        <filter id="glow-orange">
          <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
        <filter id="glow-gray">
          <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
          <feMerge>
            <feMergeNode in="coloredBlur"/>
            <feMergeNode in="SourceGraphic"/>
          </feMerge>
        </filter>
      </defs>
    `;

    // Render Edges
    this.edges.forEach(edge => {
      const src = this.nodes.find(n => n.id === edge.source);
      const tgt = this.nodes.find(n => n.id === edge.target);
      if (!src || !tgt) return;

      const isAttack = edge.status === "AttackPath";
      const isIsolated = edge.status === "Isolated";
      let strokeColor = "rgba(79, 172, 254, 0.4)";
      if (isAttack) strokeColor = "#ef4444";
      else if (isIsolated) strokeColor = "rgba(100, 116, 139, 0.5)";

      const markerId = isAttack ? "arrow-red" : "arrow";
      const strokeDash = isAttack ? "5,5" : (isIsolated ? "3,3" : "none");

      const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
      line.setAttribute("x1", src.x);
      line.setAttribute("y1", src.y);
      line.setAttribute("x2", tgt.x);
      line.setAttribute("y2", tgt.y);
      line.setAttribute("stroke", strokeColor);
      line.setAttribute("stroke-width", isAttack ? "2.5" : "1.5");
      line.setAttribute("stroke-dasharray", strokeDash);
      line.setAttribute("class", isAttack ? "edge-attack" : "edge-normal");
      line.setAttribute("marker-end", `url(#${markerId})`);

      if (isAttack) {
        line.innerHTML = `<animate attributeName="stroke-dashoffset" from="20" to="0" dur="1s" repeatCount="indefinite" />`;
      }

      this.svg.appendChild(line);
    });

    // Render Nodes
    this.nodes.forEach(node => {
      const g = document.createElementNS("http://www.w3.org/2000/svg", "g");
      g.setAttribute("transform", `translate(${node.x}, ${node.y})`);
      g.setAttribute("style", "cursor: grab;");
      
      // Node click for XAI modal, but handle drag as well
      let isDragging = false;
      
      g.onmousedown = (e) => {
        e.stopPropagation();
        this.draggedNode = node;
        isDragging = false;
      };
      
      g.onmousemove = () => {
        if (this.draggedNode) isDragging = true;
      };

      g.onclick = (e) => {
        e.stopPropagation();
        if (!isDragging && window.NetShieldApp) {
          window.NetShieldApp.openXAIModalForDevice(node);
        }
      };

      let fill = "#10b981";
      let stroke = "#059669";
      let glowClass = "";

      if (node.status === "Isolated") {
        fill = "#64748b";
        stroke = "#475569";
        glowClass = "filter: url(#glow-gray);";
      } else if (node.status === "Compromised") {
        fill = "#ef4444";
        stroke = "#dc2626";
        glowClass = "filter: url(#glow-red);";
      } else if (node.status === "Contained") {
        fill = "#f59e0b";
        stroke = "#d97706";
        glowClass = "filter: url(#glow-orange);";
      } else if (node.status === "Suspicious") {
        fill = "#f59e0b";
        stroke = "#d97706";
      }

      const riskLabel = `${node.risk}%`;
      const statusLabel = node.status === "Isolated" ? "⚪ Isolated" : node.status;
      
      // We will show the Name/Type as the primary label, and the IP address below it
      let primaryName = node.name || node.type || "Connected Device";
      if (node.id === 'my_laptop') primaryName = "My System";
      else if (primaryName.startsWith('Device (')) primaryName = "Connected Device";

      const ipLabel = node.ip;

      g.innerHTML = `
        <circle r="22" fill="${fill}" stroke="${stroke}" stroke-width="3" style="${glowClass}" />
        <circle r="14" fill="#0f172a" />
        <text y="4" text-anchor="middle" fill="${node.status === 'Isolated' ? '#94a3b8' : '#fff'}" font-size="10px" font-weight="bold">${riskLabel}</text>
        <text y="36" text-anchor="middle" fill="#f3f4f6" font-size="11px" font-weight="600">${primaryName}</text>
        <text y="48" text-anchor="middle" fill="#94a3b8" font-size="9px" font-family="monospace">${ipLabel}</text>
        <text y="58" text-anchor="middle" fill="${node.status === 'Isolated' ? '#64748b' : '#9ca3af'}" font-size="9px" font-weight="${node.status === 'Isolated' ? 'bold' : 'normal'}">${statusLabel}</text>
      `;

      this.svg.appendChild(g);
    });
  }
}

window.AttackGraphRenderer = AttackGraphRenderer;
