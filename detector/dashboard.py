"""
Live metrics dashboard — Flask web app served on port 8080.

/           HTML page (auto-refreshes every 3 seconds via JS polling)
/api/stats  JSON endpoint with all live metrics
"""

import time
import logging
import psutil
from flask import Flask, jsonify, render_template_string

logger = logging.getLogger(__name__)

_START_TIME = time.time()

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Traffic Sentinel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Courier New', monospace; background: #0d1117; color: #c9d1d9; padding: 20px; }
    h1 { color: #58a6ff; margin-bottom: 8px; font-size: 1.4em; }
    .subtitle { color: #8b949e; font-size: 0.85em; margin-bottom: 24px; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }
    .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; }
    .card h2 { color: #58a6ff; font-size: 0.9em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; }
    .metric { display: flex; justify-content: space-between; padding: 4px 0; border-bottom: 1px solid #21262d; font-size: 0.88em; }
    .metric:last-child { border-bottom: none; }
    .val { color: #79c0ff; font-weight: bold; }
    .val.danger { color: #f85149; }
    .val.warn { color: #d29922; }
    .val.ok { color: #3fb950; }
    table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
    th { color: #8b949e; text-align: left; padding: 4px 8px; border-bottom: 1px solid #30363d; }
    td { padding: 4px 8px; border-bottom: 1px solid #21262d; }
    .badge-ban { background: #3d1c1c; color: #f85149; padding: 1px 6px; border-radius: 4px; font-size: 0.8em; }
    .uptime { color: #8b949e; font-size: 0.8em; margin-top: 16px; text-align: right; }
    #last-update { color: #3fb950; font-size: 0.75em; }
    .audit { font-size: 0.78em; color: #8b949e; max-height: 200px; overflow-y: auto; }
    .audit p { padding: 2px 0; border-bottom: 1px solid #21262d; }
  </style>
</head>
<body>
  <h1>&#x1F6E1; Traffic Sentinel — Anomaly Detection Engine</h1>
  <p class="subtitle">Live dashboard &mdash; <span id="last-update">loading...</span></p>

  <div class="grid">
    <div class="card">
      <h2>Traffic</h2>
      <div class="metric"><span>Global req/s</span><span class="val" id="global-rps">—</span></div>
      <div class="metric"><span>Baseline mean</span><span class="val" id="baseline-mean">—</span></div>
      <div class="metric"><span>Baseline stddev</span><span class="val" id="baseline-stddev">—</span></div>
    </div>

    <div class="card">
      <h2>System</h2>
      <div class="metric"><span>CPU</span><span class="val" id="cpu">—</span></div>
      <div class="metric"><span>Memory</span><span class="val" id="mem">—</span></div>
      <div class="metric"><span>Uptime</span><span class="val" id="uptime">—</span></div>
    </div>

    <div class="card">
      <h2>Banned IPs (<span id="ban-count">0</span>)</h2>
      <table>
        <thead><tr><th>IP</th><th>Offenses</th><th>Expires</th></tr></thead>
        <tbody id="ban-table"></tbody>
      </table>
    </div>

    <div class="card">
      <h2>Top 10 Source IPs</h2>
      <table>
        <thead><tr><th>IP</th><th>req/s</th></tr></thead>
        <tbody id="top-table"></tbody>
      </table>
    </div>

    <div class="card" style="grid-column: 1 / -1;">
      <h2>Audit Log (last 20)</h2>
      <div class="audit" id="audit-log"></div>
    </div>
  </div>

  <div class="uptime">Detector started: <span id="start-time">—</span></div>

  <script>
    async function refresh() {
      try {
        const r = await fetch('/api/stats');
        const d = await r.json();

        document.getElementById('last-update').textContent = 'Updated: ' + new Date().toLocaleTimeString();
        document.getElementById('global-rps').textContent = d.global_rps.toFixed(2);
        document.getElementById('baseline-mean').textContent = d.baseline.effective_mean.toFixed(3);
        document.getElementById('baseline-stddev').textContent = d.baseline.effective_stddev.toFixed(3);
        document.getElementById('cpu').textContent = d.system.cpu_percent.toFixed(1) + '%';
        document.getElementById('mem').textContent = d.system.mem_percent.toFixed(1) + '%';
        document.getElementById('uptime').textContent = d.uptime;
        document.getElementById('start-time').textContent = d.start_time;
        document.getElementById('ban-count').textContent = d.banned_ips.length;

        const banTbody = document.getElementById('ban-table');
        banTbody.innerHTML = d.banned_ips.map(b => {
          const expires = b.unban_at ? new Date(b.unban_at * 1000).toLocaleTimeString() : 'permanent';
          return `<tr><td><span class="badge-ban">${b.ip}</span></td><td>${b.offense_count}</td><td>${expires}</td></tr>`;
        }).join('') || '<tr><td colspan="3" style="color:#3fb950">No active bans</td></tr>';

        const topTbody = document.getElementById('top-table');
        topTbody.innerHTML = d.top_ips.map(([ip, rate]) =>
          `<tr><td>${ip}</td><td class="val">${rate.toFixed(3)}</td></tr>`
        ).join('') || '<tr><td colspan="2">No traffic</td></tr>';

        const auditDiv = document.getElementById('audit-log');
        auditDiv.innerHTML = d.audit_log.map(l => `<p>${l}</p>`).join('');

      } catch(e) { console.error(e); }
    }
    refresh();
    setInterval(refresh, 3000);
  </script>
</body>
</html>
"""


def create_app(detector, baseline, blocker, audit_logger, start_time: float):
    app = Flask(__name__)
    app.logger.setLevel(logging.WARNING)

    @app.route("/")
    def index():
        return render_template_string(_HTML)

    @app.route("/api/stats")
    def stats():
        now = time.time()
        uptime_secs = int(now - start_time)
        h, r = divmod(uptime_secs, 3600)
        m, s = divmod(r, 60)

        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()

        return jsonify({
            "global_rps": detector.global_rate(),
            "top_ips": detector.top_ips(10),
            "banned_ips": blocker.banned_snapshot(),
            "baseline": baseline.snapshot(),
            "system": {
                "cpu_percent": cpu,
                "mem_percent": mem.percent,
                "mem_used_mb": round(mem.used / 1024 / 1024, 1),
            },
            "uptime": f"{h}h {m}m {s}s",
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start_time)),
            "audit_log": audit_logger.tail(20),
        })

    return app
