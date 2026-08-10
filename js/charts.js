/**
 * NetShield AI - Charts & Live Canvas Telemetry Visualization Engine
 */

class TelemetryChart {
  constructor(canvasId) {
    this.canvas = document.getElementById(canvasId);
    if (!this.canvas) return;
    this.ctx = this.canvas.getContext('2d');
    this.dataPoints = Array(30).fill(12);
    this.threatPoints = Array(30).fill(0);
    this.resizeCanvas();
    window.addEventListener('resize', () => this.resizeCanvas());
  }

  resizeCanvas() {
    if (!this.canvas) return;
    this.canvas.width = this.canvas.parentElement.clientWidth;
    this.canvas.height = this.canvas.parentElement.clientHeight || 200;
  }

  pushData(throughput, threatCount) {
    this.dataPoints.shift();
    this.dataPoints.push(throughput);
    this.threatPoints.shift();
    this.threatPoints.push(threatCount);
    this.render();
  }

  render() {
    if (!this.ctx) return;
    const w = this.canvas.width;
    const h = this.canvas.height;
    const ctx = this.ctx;

    ctx.clearRect(0, 0, w, h);

    // Draw Grid Lines
    ctx.strokeStyle = 'rgba(45, 62, 98, 0.2)';
    ctx.lineWidth = 1;
    for (let y = 0; y < h; y += 40) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
      ctx.stroke();
    }

    const step = w / (this.dataPoints.length - 1);
    const maxVal = Math.max(...this.dataPoints, 100);

    // Fill Gradient under Throughput Curve
    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, 'rgba(0, 242, 254, 0.35)');
    gradient.addColorStop(1, 'rgba(0, 242, 254, 0.0)');

    ctx.beginPath();
    ctx.moveTo(0, h);

    for (let i = 0; i < this.dataPoints.length; i++) {
      const x = i * step;
      const val = this.dataPoints[i];
      const y = h - (val / maxVal) * (h - 30) - 15;
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    }

    ctx.lineTo(w, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw Main Throughput Stroke
    ctx.beginPath();
    for (let i = 0; i < this.dataPoints.length; i++) {
      const x = i * step;
      const val = this.dataPoints[i];
      const y = h - (val / maxVal) * (h - 30) - 15;
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = '#00f2fe';
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Draw Threat Points in Red Overlay
    ctx.beginPath();
    for (let i = 0; i < this.threatPoints.length; i++) {
      const x = i * step;
      const val = this.threatPoints[i];
      if (val > 0) {
        const y = h - (val / 10) * (h - 40) - 20;
        ctx.fillStyle = '#ef4444';
        ctx.beginPath();
        ctx.arc(x, y, 5, 0, Math.PI * 2);
        ctx.fill();
        ctx.shadowColor = '#ef4444';
        ctx.shadowBlur = 10;
      }
    }
    ctx.shadowBlur = 0;
  }
}

window.TelemetryChart = TelemetryChart;
