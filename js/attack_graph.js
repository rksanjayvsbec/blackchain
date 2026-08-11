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
