"""
Anomaly detector.

Uses two deque-based sliding windows (per-IP and global) over the last
60 seconds.  On each incoming log entry it:

  1. Updates the per-IP request window and per-IP error window.
  2. Updates the global request window.
  3. Computes current req/s rates.
  4. Flags anomalies when z-score > threshold OR rate > N × baseline mean.
  5. If an IP has an elevated error rate it tightens its detection thresholds.
  6. Calls blocker/notifier for per-IP anomalies; notifier-only for global.
"""

import math
import threading
import time
import logging
from collections import defaultdict, deque
from typing import Callable, Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class SlidingWindow:
    """
    Deque-based sliding window.

    Stores raw timestamps.  Entries older than `window_seconds` are
    evicted lazily on every read or write.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._ts: deque = deque()

    def add(self, ts: Optional[float] = None):
        now = ts or time.time()
        self._ts.append(now)
        self._evict(now)

    def _evict(self, now: float):
        cutoff = now - self.window_seconds
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()

    def count(self, now: Optional[float] = None) -> int:
        now = now or time.time()
        self._evict(now)
        return len(self._ts)

    def rate(self, now: Optional[float] = None) -> float:
        """Requests per second over the window."""
        return self.count(now) / self.window_seconds


class AnomalyDetector:
    def __init__(
        self,
        baseline,
        blocker,
        notifier,
        audit_logger,
        window_seconds: int = 60,
        zscore_threshold: float = 3.0,
        rate_multiplier: float = 5.0,
        error_rate_multiplier: float = 3.0,
        error_tightening: float = 0.7,
    ):
        self._baseline = baseline
        self._blocker = blocker
        self._notifier = notifier
        self._audit = audit_logger

        self._window_seconds = window_seconds
        self._zscore_threshold = zscore_threshold
        self._rate_multiplier = rate_multiplier
        self._error_rate_multiplier = error_rate_multiplier
        self._error_tightening = error_tightening  # multiply threshold by this factor

        # Per-IP windows
        self._ip_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_seconds)
        )
        self._ip_error_windows: Dict[str, SlidingWindow] = defaultdict(
            lambda: SlidingWindow(window_seconds)
        )

        # Global window
        self._global_window = SlidingWindow(window_seconds)

        self._lock = threading.Lock()

        # Prevent duplicate alerts within the same burst
        self._alerted_ips: Dict[str, float] = {}  # ip -> last_alert_time
        self._global_alert_time: float = 0.0
        self._alert_cooldown = 30  # seconds between repeat alerts for same IP

    # ------------------------------------------------------------------ #

    def process(self, entry: dict):
        """Called for every parsed log line."""
        ip = entry.get("source_ip", "unknown")
        ts_str = entry.get("timestamp", "")
        status = int(entry.get("status", 200))
        is_error = status >= 400

        # Use log timestamp if parseable, else wall clock
        ts = self._parse_ts(ts_str)

        with self._lock:
            self._ip_windows[ip].add(ts)
            if is_error:
                self._ip_error_windows[ip].add(ts)
            self._global_window.add(ts)

        self._check_ip(ip, ts)
        self._check_global(ts)

    def _check_ip(self, ip: str, now: float):
        mean = self._baseline.effective_mean
        stddev = self._baseline.effective_stddev
        err_mean = self._baseline.effective_error_mean
        err_stddev = self._baseline.effective_error_stddev

        with self._lock:
            ip_rate = self._ip_windows[ip].rate(now)
            ip_err_rate = self._ip_error_windows[ip].rate(now)

        # Skip if baseline not yet established
        if mean < 0.001:
            return

        # Check if this IP has an error surge — tighten thresholds if so
        z_thresh = self._zscore_threshold
        mult_thresh = self._rate_multiplier
        if err_mean > 0.001:
            err_zscore = (ip_err_rate - err_mean) / err_stddev
            if err_zscore > self._error_rate_multiplier or ip_err_rate > self._error_rate_multiplier * err_mean:
                z_thresh *= self._error_tightening
                mult_thresh *= self._error_tightening
                logger.debug("IP %s has error surge — thresholds tightened", ip)

        # Compute z-score for this IP's rate
        ip_zscore = (ip_rate - mean) / stddev

        fired = False
        condition = ""
        if ip_zscore > z_thresh:
            fired = True
            condition = f"z-score={ip_zscore:.2f} > {z_thresh}"
        elif mean > 0 and ip_rate > mult_thresh * mean:
            fired = True
            condition = f"rate={ip_rate:.2f}/s > {mult_thresh}x baseline ({mean:.2f}/s)"

        if fired and not self._is_already_banned(ip):
            cooldown_ok = (now - self._alerted_ips.get(ip, 0)) > self._alert_cooldown
            if cooldown_ok:
                self._alerted_ips[ip] = now
                logger.warning("Anomaly detected for IP %s: %s", ip, condition)
                duration = self._blocker.ban(ip)
                self._notifier.ban_alert(ip, condition, ip_rate, mean, duration)
                self._audit.log_ban(ip, condition, ip_rate, mean, duration)

    def _check_global(self, now: float):
        mean = self._baseline.effective_mean
        stddev = self._baseline.effective_stddev

        if mean < 0.001:
            return

        with self._lock:
            global_rate = self._global_window.rate(now)

        global_zscore = (global_rate - mean) / stddev

        fired = False
        condition = ""
        if global_zscore > self._zscore_threshold:
            fired = True
            condition = f"global z-score={global_zscore:.2f} > {self._zscore_threshold}"
        elif mean > 0 and global_rate > self._rate_multiplier * mean:
            fired = True
            condition = f"global rate={global_rate:.2f}/s > {self._rate_multiplier}x baseline"

        if fired:
            cooldown_ok = (now - self._global_alert_time) > self._alert_cooldown
            if cooldown_ok:
                self._global_alert_time = now
                logger.warning("Global anomaly: %s", condition)
                self._notifier.global_alert(condition, global_rate, mean)
                self._audit.log_global_anomaly(condition, global_rate, mean)

    def _is_already_banned(self, ip: str) -> bool:
        return self._blocker.is_banned(ip)

    def top_ips(self, n: int = 10) -> List[Tuple[str, float]]:
        now = time.time()
        with self._lock:
            rates = {
                ip: w.rate(now)
                for ip, w in self._ip_windows.items()
                if w.count(now) > 0
            }
        return sorted(rates.items(), key=lambda x: x[1], reverse=True)[:n]

    def global_rate(self) -> float:
        with self._lock:
            return self._global_window.rate()

    @staticmethod
    def _parse_ts(ts_str: str) -> float:
        """Parse ISO8601 timestamp from nginx log; fall back to time.time()."""
        try:
            from datetime import datetime, timezone
            # Nginx ISO8601: 2024-01-01T12:00:00+00:00
            dt = datetime.fromisoformat(ts_str)
            return dt.timestamp()
        except Exception:
            return time.time()
