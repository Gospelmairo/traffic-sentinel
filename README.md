# Anomaly Detection Engine

**Server IP:** `3.236.146.31`
**Metrics Dashboard:** `http://traffic-sentinel.duckdns.org:8080`
**GitHub Repo:** `https://github.com/Gospelmairo/traffic-sentinel`
**Blog Post:** `https://mairogospel.hashnode.dev/how-i-built-a-real-time-ddos-detection-engine-from-scratch`

---

## Language

Python  chosen for fast iteration, strong stdlib support for threading and deques, and readable detection logic that can be audited at a glance.

---

## How the Sliding Window Works

Two `collections.deque` structures track raw timestamps:

- **Per-IP window** — one deque per source IP, stores UNIX timestamps of every request from that IP in the last 60 seconds.
- **Global window** — one deque for all traffic combined.

**Eviction logic:** On every read or write, entries older than `now - 60s` are popped from the left of the deque (`popleft()`). Since timestamps are always appended in chronological order, the oldest entry is always at index 0 — making eviction O(1) per expired entry.

```python
def _evict(self, now: float):
    cutoff = now - self.window_seconds
    while self._ts and self._ts[0] < cutoff:
        self._ts.popleft()

def rate(self) -> float:
    self._evict(time.time())
    return len(self._ts) / self.window_seconds  # req/s
```

No rate-limiting libraries are used — just deques and arithmetic.

---

## How the Baseline Works

- **Window:** 30 minutes of per-second request counts.
- **Recalculation:** Every 60 seconds, mean and stddev are recomputed from the window.
- **Per-hour slots:** Counts are also stored by `(year, month, day, hour)` key. When the current hour slot has ≥ 10 data points, it is preferred over the full 30-minute window  this makes the baseline sensitive to time-of-day traffic patterns.
- **Floor values:** stddev is floored at `0.1` to prevent division by zero. Mean below `0.001` suppresses all anomaly checks until baseline is established.

---

## Detection Logic

For each incoming request, the detector computes the current req/s rate for the IP and globally, then checks:

1. **Z-score check:** `(rate - mean) / stddev > 3.0`
2. **Multiplier check:** `rate > 5x mean`

Whichever fires first triggers an alert. For **error surges** (4xx/5xx rate ≥ 3× baseline error rate), both thresholds are tightened by 30% — making the IP easier to flag.

---

## How iptables Blocks an IP

When a per-IP anomaly fires, the blocker runs:

```bash
iptables -A INPUT -s <ip> -j DROP
```

This adds a DROP rule to the INPUT chain  all subsequent packets from that IP are silently discarded at the kernel level before they reach Nginx or Nextcloud. On unban:

```bash
iptables -D INPUT -s <ip> -j DROP
```

Bans follow a backoff schedule: 10 min → 30 min → 2 hours → permanent.

---

## Setup — Fresh VPS to Running Stack

```bash
# 1. Install Docker
sudo apt-get update -y
sudo apt-get install -y docker.io docker-compose-plugin
sudo systemctl enable --now docker

# 2. Clone repo
git clone https://github.com/Gospelmairo/traffic-sentinel.git
cd traffic-sentinel

# 3. Configure
cp detector/config.yaml detector/config.yaml.local
# Edit config.yaml — set your Slack webhook URL
nano detector/config.yaml

# 4. Set your server IP (for Nextcloud trusted domains)
echo "SERVER_IP=$(curl -s ifconfig.me)" > .env

# 5. Start stack
docker compose up -d --build

# 6. Open firewall ports
sudo ufw allow 80/tcp
sudo ufw allow 8080/tcp

# 7. Verify
curl http://localhost/                         # Nextcloud
curl http://localhost:8080/api/stats           # Detector metrics
```

---

## Repository Structure

```
detector/
  main.py          Entry point, starts all threads
  monitor.py       Nginx log tailer and JSON parser
  baseline.py      Rolling 30-min baseline with per-hour slots
  detector.py      Anomaly detection (z-score + multiplier)
  blocker.py       iptables ban/unban management
  unbanner.py      Auto-unban daemon (backoff schedule)
  notifier.py      Slack webhook notifications
  dashboard.py     Flask live metrics UI
  audit.py         Structured audit log writer
  config.yaml      All thresholds and configuration
  requirements.txt Python dependencies
  Dockerfile
nginx/
  nginx.conf       JSON access logs + X-Forwarded-For
docs/
  architecture.png
screenshots/
README.md
docker-compose.yml
```
