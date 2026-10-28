package apigateway

import (
	"net/http"
	"strings"
)

const webhookPortalHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Aeitron Webhooks Developer Portal — Real-Time HUD</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><rect width='100' height='100' rx='20' fill='%236366f1'/><path d='M30 70 L50 30 L70 70 Z' fill='none' stroke='white' stroke-width='8'/></svg>">
  <style>
    :root {
      --bg: #090d16;
      --card-bg: #111827;
      --card-border: rgba(255, 255, 255, 0.08);
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      line-height: 1.5;
      padding-bottom: 60px;
    }
    header {
      background: rgba(17, 24, 39, 0.95);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--card-border);
      padding: 16px 28px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 100;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      font-weight: 700;
      font-size: 17px;
      letter-spacing: -0.02em;
    }
    .brand svg { width: 28px; height: 28px; }
    .badge {
      font-size: 11px;
      padding: 3px 8px;
      border-radius: 9999px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .badge-primary { background: rgba(99, 102, 241, 0.2); color: #818cf8; border: 1px solid rgba(99, 102, 241, 0.4); }
    .badge-live {
      background: rgba(16, 185, 129, 0.15);
      color: #34d399;
      border: 1px solid rgba(16, 185, 129, 0.4);
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 8px #10b981;
      animation: pulse 1.5s infinite;
    }
    @keyframes pulse {
      0% { transform: scale(0.9); opacity: 0.7; }
      50% { transform: scale(1.2); opacity: 1; }
      100% { transform: scale(0.9); opacity: 0.7; }
    }
    .container {
      max-width: 1360px;
      margin: 28px auto;
      padding: 0 24px;
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 24px;
    }
    @media (max-width: 1024px) {
      .container { grid-template-columns: 1fr; }
    }
    .full-width { grid-column: 1 / -1; }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      border-radius: 12px;
      padding: 24px;
      box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
    }
    .card-title {
      font-size: 16px;
      font-weight: 600;
      margin-bottom: 16px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      color: #fff;
    }
    label {
      display: block;
      font-size: 13px;
      color: var(--text-muted);
      margin-bottom: 6px;
      font-weight: 500;
    }
    input, select, textarea {
      width: 100%;
      background: #1f2937;
      border: 1px solid var(--card-border);
      color: #fff;
      padding: 10px 14px;
      border-radius: 8px;
      font-size: 14px;
      margin-bottom: 16px;
      outline: none;
      transition: border-color 0.15s;
    }
    input:focus, select:focus, textarea:focus {
      border-color: var(--primary);
    }
    textarea {
      font-family: var(--font-mono);
      font-size: 13px;
      min-height: 120px;
      resize: vertical;
    }
    button {
      background: var(--primary);
      color: #fff;
      border: none;
      padding: 10px 18px;
      border-radius: 8px;
      font-weight: 600;
      font-size: 14px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      transition: background 0.15s;
    }
    button:hover { background: var(--primary-hover); }
    button.btn-secondary {
      background: #374151;
      color: var(--text);
    }
    button.btn-secondary:hover { background: #4b5563; }
    .table-container {
      overflow-x: auto;
      border: 1px solid var(--card-border);
      border-radius: 8px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      text-align: left;
      font-size: 13px;
    }
    th, td {
      padding: 12px 16px;
      border-bottom: 1px solid var(--card-border);
    }
    th {
      background: rgba(31, 41, 55, 0.5);
      color: var(--text-muted);
      font-weight: 600;
      text-transform: uppercase;
      font-size: 11px;
      letter-spacing: 0.05em;
    }
    tr:hover { background: rgba(255, 255, 255, 0.02); }
    .status-badge {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
    }
    .status-2xx { background: rgba(16, 185, 129, 0.2); color: #34d399; }
    .status-4xx { background: rgba(245, 158, 11, 0.2); color: #fbbf24; }
    .status-5xx { background: rgba(239, 68, 68, 0.2); color: #f87171; }
    .code-box {
      background: #0d1117;
      border: 1px solid var(--card-border);
      padding: 14px;
      border-radius: 8px;
      font-family: var(--font-mono);
      font-size: 12px;
      color: #93c5fd;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .timeline {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin: 20px 0;
      position: relative;
    }
    .timeline::before {
      content: '';
      position: absolute;
      top: 50%;
      left: 0;
      right: 0;
      height: 2px;
      background: rgba(255, 255, 255, 0.1);
      z-index: 1;
    }
    .timeline-step {
      position: relative;
      z-index: 2;
      background: var(--card-bg);
      border: 2px solid var(--primary);
      width: 32px;
      height: 32px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: bold;
      font-size: 12px;
    }
    .timeline-label {
      text-align: center;
      margin-top: 8px;
      font-size: 11px;
      color: var(--text-muted);
    }
    .tab-bar {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      padding-bottom: 8px;
    }
    .tab-btn {
      background: transparent;
      color: var(--text-muted);
      padding: 6px 12px;
      font-size: 13px;
    }
    .tab-btn.active {
      background: rgba(99, 102, 241, 0.2);
      color: #818cf8;
      border: 1px solid rgba(99, 102, 241, 0.4);
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect width="100" height="100" rx="20" fill="#6366f1"/>
        <path d="M30 70 L50 30 L70 70 Z" stroke="white" stroke-width="8" stroke-linejoin="round"/>
      </svg>
      <span>Aeitron Infrastructure</span>
      <span class="badge badge-primary">Webhook HUD</span>
    </div>
    <div style="display: flex; align-items: center; gap: 16px;">
      <span id="sseStatusBadge" class="badge badge-live">
        <span class="pulse-dot"></span> Real-Time SSE Active
      </span>
      <a href="/docs" target="_blank" style="color: var(--text-muted); text-decoration: none; font-size: 13px;">API Reference ↗</a>
    </div>
  </header>

  <div class="container">
    <!-- Section 1: Live Interactive Webhook Simulator -->
    <div class="card">
      <div class="card-title">
        <span>⚡ Interactive Webhook Simulator</span>
        <span class="badge badge-primary">Live Test Engine</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 18px;">
        Dispatch synchronous test events to your endpoint with HMAC-SHA256 signature generation and real-time failure diagnostics.
      </p>

      <form id="webhookTestForm">
        <label for="destUrl">Destination Webhook URL</label>
        <input type="url" id="destUrl" required placeholder="https://your-api.com/webhooks or http://localhost:8080/wh" value="https://httpbin.org/post">

        <div style="display: grid; grid-template-columns: 2fr 1fr; gap: 12px;">
          <div>
            <label for="whSecret">Signing Secret</label>
            <input type="text" id="whSecret" placeholder="whsec_..." value="whsec_demo_secret_key_123456789">
          </div>
          <div>
            <label>&nbsp;</label>
            <button type="button" class="btn-secondary" style="width: 100%;" onclick="generateSecret()">🎲 Random</button>
          </div>
        </div>

        <label for="eventType">Cloud Event Type</label>
        <select id="eventType">
          <option value="compute.instance.provisioned">compute.instance.provisioned</option>
          <option value="dns.failover_triggered">dns.failover_triggered</option>
          <option value="cluster.deployment_succeeded">cluster.deployment_succeeded</option>
          <option value="invoice.payment_succeeded">invoice.payment_succeeded</option>
          <option value="ddos.attack_mitigated">ddos.attack_mitigated</option>
          <option value="custom.test_ping">custom.test_ping</option>
        </select>

        <label for="eventPayload">Simulated JSON Payload</label>
        <textarea id="eventPayload">{
  "instance_id": "vm_sin_001",
  "region": "ap-southeast-1",
  "pop": "pop-sin-01",
  "status": "running",
  "specs": { "cores": 8, "ram_gb": 32 }
}</textarea>

        <div style="display: flex; gap: 12px; align-items: center;">
          <button type="submit" id="btnSendTest">🚀 Send Test Webhook</button>
          <span id="testLoading" style="display: none; font-size: 13px; color: var(--text-muted);">Dispatching...</span>
        </div>
      </form>

      <!-- Live Test Result Output Box -->
      <div id="testResultBox" style="display: none; margin-top: 20px;">
        <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
          <strong style="font-size: 13px;">Execution Result:</strong>
          <span id="testStatusBadge" class="status-badge status-2xx">200 OK</span>
        </div>
        <div class="code-box" id="testResultContent"></div>
      </div>
    </div>

    <!-- Section 2: Exponential Backoff & Delivery Lifecycle Visualizer -->
    <div class="card">
      <div class="card-title">
        <span>🔄 Exponential Backoff Lifecycle</span>
        <span class="badge badge-primary">RFC 9110 / Stripe Style</span>
      </div>
      <p style="font-size: 13px; color: var(--text-muted);">
        Aeitron automatically retries failed deliveries using exponential backoff with full jitter to protect your servers from thundering herds.
      </p>

      <div class="timeline">
        <div>
          <div class="timeline-step">1</div>
          <div class="timeline-label">Immediate<br>0s</div>
        </div>
        <div>
          <div class="timeline-step">2</div>
          <div class="timeline-label">+1s<br>Retry 1</div>
        </div>
        <div>
          <div class="timeline-step">3</div>
          <div class="timeline-label">+2s<br>Retry 2</div>
        </div>
        <div>
          <div class="timeline-step">4</div>
          <div class="timeline-label">+4s<br>Retry 3</div>
        </div>
        <div>
          <div class="timeline-step">5</div>
          <div class="timeline-label">+8s<br>Retry 4</div>
        </div>
        <div>
          <div class="timeline-step" style="border-color: var(--danger); color: var(--danger);">DLQ</div>
          <div class="timeline-label">Dead-Letter<br>Queue</div>
        </div>
      </div>

      <div class="tab-bar">
        <button class="tab-btn active" onclick="switchSnippet('node')">Node.js</button>
        <button class="tab-btn" onclick="switchSnippet('python')">Python</button>
        <button class="tab-btn" onclick="switchSnippet('go')">Go</button>
        <button class="tab-btn" onclick="switchSnippet('rust')">Rust</button>
      </div>

      <div id="codeSnippet" class="code-box">// Verify X-Aeitron-Signature in Node.js
const crypto = require('crypto');
function verifySignature(payload, signatureHeader, secret) {
  const parts = signatureHeader.split(',');
  const ts = parts.find(p => p.startsWith('t=')).split('=')[1];
  const sig = parts.find(p => p.startsWith('v1=')).split('=')[1];
  const expected = crypto.createHmac('sha256', secret)
    .update(ts + '.' + payload).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));
}</div>
    </div>

    <!-- Section 3: Live Deliveries HUD Feed (Full Width) -->
    <div class="card full-width">
      <div class="card-title">
        <span>📡 Live Deliveries Stream (Real-Time Feed)</span>
        <button class="btn-secondary" onclick="loadDeliveries()">🔄 Refresh Feed</button>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Delivery ID</th>
              <th>Event Type</th>
              <th>Destination URL</th>
              <th>Attempt</th>
              <th>Status</th>
              <th>Latency</th>
              <th>Timestamp</th>
            </tr>
          </thead>
          <tbody id="deliveriesTableBody">
            <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">Listening for live real-time events via Server-Sent Events (SSE)...</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Section 4: Dead-Letter Queue (DLQ) & 1-Click Forensic Redelivery -->
    <div class="card full-width">
      <div class="card-title">
        <span style="display: flex; align-items: center; gap: 8px;">
          <span style="color: var(--danger);">☠️</span> Dead-Letter Queue (DLQ)
        </span>
        <button class="btn-secondary" onclick="loadDeadLetters()">🔄 Refresh DLQ</button>
      </div>
      <p style="font-size: 13px; color: var(--text-muted); margin-bottom: 16px;">
        Deliveries that exhausted all retry attempts are quarantined here. Inspect error traces and trigger immediate manual redelivery.
      </p>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Delivery ID</th>
              <th>Event ID</th>
              <th>Event Type</th>
              <th>Destination URL</th>
              <th>Final Error Reason</th>
              <th>Failed At</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="dlqTableBody">
            <tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No failed webhooks in Dead-Letter Queue.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <script>
    function generateSecret() {
      const hex = Array.from(crypto.getRandomValues(new Uint8Array(16)))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      document.getElementById('whSecret').value = 'whsec_' + hex;
    }

    // Interactive Test Dispatch Form
    document.getElementById('webhookTestForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = document.getElementById('btnSendTest');
      const loader = document.getElementById('testLoading');
      const resultBox = document.getElementById('testResultBox');
      const resultContent = document.getElementById('testResultContent');
      const statusBadge = document.getElementById('testStatusBadge');

      btn.disabled = true;
      loader.style.display = 'inline';

      try {
        let payload = {};
        try {
          payload = JSON.parse(document.getElementById('eventPayload').value);
        } catch (err) {
          alert('Invalid JSON in simulated payload');
          btn.disabled = false;
          loader.style.display = 'none';
          return;
        }

        const res = await fetch('/v1/webhooks/test', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url: document.getElementById('destUrl').value,
            secret: document.getElementById('whSecret').value,
            event_type: document.getElementById('eventType').value,
            data: payload
          })
        });

        const data = await res.json();
        resultBox.style.display = 'block';
        statusBadge.textContent = data.status_code ? (data.status_code + ' HTTP') : 'FAILED';
        statusBadge.className = 'status-badge ' + (data.success ? 'status-2xx' : 'status-5xx');

        resultContent.textContent = JSON.stringify(data, null, 2);
      } catch (err) {
        resultBox.style.display = 'block';
        statusBadge.textContent = 'NETWORK ERROR';
        statusBadge.className = 'status-badge status-5xx';
        resultContent.textContent = String(err);
      } finally {
        btn.disabled = false;
        loader.style.display = 'none';
        loadDeliveries();
      }
    });

    // Real-Time Server-Sent Events (SSE) Listener
    function setupSSEStream() {
      const sseStatus = document.getElementById('sseStatusBadge');
      const evtSource = new EventSource('/v1/events/stream?topics=webhooks.*,compute.*,dns.*');

      evtSource.onopen = () => {
        sseStatus.className = 'badge badge-live';
        sseStatus.innerHTML = '<span class="pulse-dot"></span> Real-Time SSE Active';
      };

      evtSource.onerror = () => {
        sseStatus.className = 'badge';
        sseStatus.style.background = '#374151';
        sseStatus.style.color = '#9ca3af';
        sseStatus.innerHTML = '⚠️ Reconnecting SSE...';
      };

      evtSource.addEventListener('webhook.delivery', (event) => {
        try {
          const item = JSON.parse(event.data);
          prependDeliveryRow(item);
        } catch (_) {}
      });

      evtSource.addEventListener('webhook.dead_letter', (event) => {
        loadDeadLetters();
      });
    }

    function prependDeliveryRow(item) {
      const tbody = document.getElementById('deliveriesTableBody');
      if (tbody.children.length === 1 && tbody.children[0].children.length === 1) {
        tbody.innerHTML = '';
      }
      const tr = document.createElement('tr');
      const isOk = item.status === 'success' || (item.status_code >= 200 && item.status_code < 300);
      const badgeCls = isOk ? 'status-2xx' : (item.status === 'retrying' ? 'status-4xx' : 'status-5xx');

      tr.innerHTML = 
        '<td style="font-family: var(--font-mono); color: #818cf8;">' + (item.id || 'del_live') + '</td>' +
        '<td><strong>' + (item.event_type || 'event') + '</strong></td>' +
        '<td style="color: var(--text-muted);">' + (item.url || '-') + '</td>' +
        '<td>' + (item.attempt || 1) + ' / ' + (item.max_attempts || 5) + '</td>' +
        '<td><span class="status-badge ' + badgeCls + '">' + (item.status || item.status_code || 'OK') + '</span></td>' +
        '<td>' + (item.duration_ms || 0) + 'ms</td>' +
        '<td style="color: var(--text-muted); font-size: 12px;">Just now</td>';
      tbody.prepend(tr);
    }

    async function loadDeliveries() {
      try {
        const res = await fetch('/v1/webhooks/deliveries');
        if (!res.ok) return;
        const data = await res.json();
        const deliveries = data.deliveries || [];
        const tbody = document.getElementById('deliveriesTableBody');
        if (deliveries.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No recent deliveries recorded.</td></tr>';
          return;
        }
        tbody.innerHTML = deliveries.map(d => {
          const isOk = d.status === 'success' || (d.status_code >= 200 && d.status_code < 300);
          const badgeCls = isOk ? 'status-2xx' : (d.status === 'retrying' ? 'status-4xx' : 'status-5xx');
          return '<tr>' +
            '<td style="font-family: var(--font-mono); color: #818cf8;">' + d.id + '</td>' +
            '<td><strong>' + d.event_type + '</strong></td>' +
            '<td style="color: var(--text-muted);">' + d.url + '</td>' +
            '<td>' + d.attempt + ' / ' + d.max_attempts + '</td>' +
            '<td><span class="status-badge ' + badgeCls + '">' + d.status + ' (' + (d.status_code || 0) + ')</span></td>' +
            '<td>' + d.duration_ms + 'ms</td>' +
            '<td style="color: var(--text-muted); font-size: 12px;">' + new Date(d.created_at).toLocaleTimeString() + '</td>' +
            '</tr>';
        }).join('');
      } catch (_) {}
    }

    async function loadDeadLetters() {
      try {
        const res = await fetch('/v1/webhooks/dead-letter');
        if (!res.ok) return;
        const data = await res.json();
        const dlq = data.dead_letters || [];
        const tbody = document.getElementById('dlqTableBody');
        if (dlq.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; color: var(--text-muted); padding: 24px;">No failed webhooks in Dead-Letter Queue.</td></tr>';
          return;
        }
        tbody.innerHTML = dlq.map(item => {
          return '<tr>' +
            '<td style="font-family: var(--font-mono); color: #f87171;">' + item.delivery.id + '</td>' +
            '<td style="font-family: var(--font-mono);">' + item.delivery.event_id + '</td>' +
            '<td><strong>' + item.delivery.event_type + '</strong></td>' +
            '<td style="color: var(--text-muted);">' + item.delivery.url + '</td>' +
            '<td style="color: #f87171; font-size: 12px;">' + (item.reason || item.delivery.error || 'Max retries exhausted') + '</td>' +
            '<td style="color: var(--text-muted); font-size: 12px;">' + new Date(item.failed_at).toLocaleTimeString() + '</td>' +
            '<td><button class="btn-secondary" style="padding: 4px 10px; font-size: 12px;" onclick="redeliver(\'' + item.delivery.id + '\')">🔄 Redeliver</button></td>' +
            '</tr>';
        }).join('');
      } catch (_) {}
    }

    async function redeliver(deliveryId) {
      try {
        const res = await fetch('/v1/webhooks/dead-letter/retry', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ delivery_id: deliveryId })
        });
        if (res.ok) {
          alert('Webhook enqueued for redelivery!');
          loadDeadLetters();
          loadDeliveries();
        } else {
          alert('Failed to redeliver webhook item');
        }
      } catch (err) {
        alert('Redelivery request error: ' + err);
      }
    }

    const snippets = {
      node: '// Node.js (Crypto module)\n' +
        'const crypto = require(\'crypto\');\n' +
        'function verifyWebhook(body, sigHeader, secret) {\n' +
        '  const [tPart, vPart] = sigHeader.split(\',\');\n' +
        '  const ts = tPart.split(\'=\')[1];\n' +
        '  const sig = vPart.split(\'=\')[1];\n' +
        '  const expected = crypto.createHmac(\'sha256\', secret)\n' +
        '    .update(ts + \'.\' + body).digest(\'hex\');\n' +
        '  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected));\n' +
        '}',
      python: '# Python (hmac + hashlib)\n' +
        'import hmac, hashlib\n\n' +
        'def verify_webhook(body_bytes: bytes, sig_header: str, secret: str) -> bool:\n' +
        '    parts = dict(p.split(\'=\') for p in sig_header.split(\',\'))\n' +
        '    ts, sig = parts[\'t\'], parts[\'v1\']\n' +
        '    expected = hmac.new(secret.encode(), (ts + \'.\').encode() + body_bytes, hashlib.sha256).hexdigest()\n' +
        '    return hmac.compare_digest(sig, expected)',
      go: '// Go (crypto/hmac)\n' +
        'func VerifyWebhook(body []byte, sigHeader, secret string) bool {\n' +
        '    parts := strings.Split(sigHeader, ",")\n' +
        '    ts := strings.TrimPrefix(parts[0], "t=")\n' +
        '    sig := strings.TrimPrefix(parts[1], "v1=")\n' +
        '    mac := hmac.New(sha256.New, []byte(secret))\n' +
        '    mac.Write([]byte(ts + "."))\n' +
        '    mac.Write(body)\n' +
        '    return hmac.Equal([]byte(sig), []byte(hex.EncodeToString(mac.Sum(nil))))\n' +
        '}',
      rust: '// Rust (hmac + sha2)\n' +
        'use hmac::{Hmac, Mac};\n' +
        'use sha2::Sha256;\n\n' +
        'pub fn verify_webhook(body: &[u8], ts: &str, sig: &str, secret: &[u8]) -> bool {\n' +
        '    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();\n' +
        '    mac.update(format!("{}.", ts).as_bytes());\n' +
        '    mac.update(body);\n' +
        '    mac.verify_slice(&hex::decode(sig).unwrap()).is_ok()\n' +
        '}'
    };

    function switchSnippet(lang) {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      event.target.classList.add('active');
      document.getElementById('codeSnippet').textContent = snippets[lang];
    }

    // Auto-init on page load
    window.addEventListener('DOMContentLoaded', () => {
      setupSSEStream();
      loadDeliveries();
      loadDeadLetters();
    });
  </script>
</body>
</html>
`

// ServeWebhookPortal renders the interactive Webhook Developer Portal HUD.
func ServeWebhookPortal(w http.ResponseWriter, r *http.Request) bool {
	path := strings.TrimSuffix(r.URL.Path, "/")
	if path == "/v1/webhooks/portal" || path == "/webhooks/portal" || path == "/portal" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(webhookPortalHTML))
		return true
	}
	return false
}
