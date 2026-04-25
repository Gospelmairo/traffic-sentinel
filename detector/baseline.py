"""
Rolling baseline tracker.

Maintains a 30-minute sliding window of per-second request counts and
computes mean + stddev.  Per-hour slots allow the detector to prefer
the current hour's baseline once enough data is available.

Recalculation runs every `recalc_seconds` (default 60).
"""

import math
import threading
import time
import logging
from collections import deque
from typing import Tuple, Dict

logger = logging.getLogger(__name__)

# Minimum distinct seconds of data before we trust a baseline slot
_MIN_SECONDS = 10


class BaselineTracker:
    def __init__(
        self,
        window_minutes: int = 30,
        recalc_seconds: int = 60,
        min_samples: int = 10,
    ):
        self._window_seconds = window_minutes * 60
        self._recalc_seconds = recalc_seconds
        self._min_samples = min_samples

        # Global rolling window: deque of (second_bucket, count) pairs
        # second_bucket = int(time.time())
        self._global_counts: deque = deque()

        # Per-hour slots: {hour_key: deque of per-second counts (ints)}
        # hour_key = (year, month, day, hour)  tuple
        self._hourly_slots: Dict[tuple, deque] = {}

        # Error rate tracking (same structure)
        self._global_error_counts: deque = deque()
        self._hourly_error_slots: Dict[tuple, deque] = {}

        # Bucket accumulator — count requests within current second
        self._current_bucket: int = int(time.time())
        self._bucket_count: int = 0
        self._bucket_error_count: int = 0

        # Published effective baseline (updated by recalc thread)
        self.effective_mean: float = 0.0
        self.effective_stddev: float = 1.0
        self.effective_error_mean: float = 0.0
        self.effective_error_stddev: float = 1.0

        self._lock = threading.Lock()

    # ------------------------------------------------------------------ #
    # Public API called by the monitor on every log line                   #
    # ------------------------------------------------------------------ #

    def record(self, timestamp: float, is_error: bool = False):
        """Record one request at the given unix timestamp."""
        bucket = int(timestamp)
        with self._lock:
            if bucket != self._current_bucket:
                self._flush_bucket()
                self._current_bucket = bucket
                self._bucket_count = 0
                self._bucket_error_count = 0
            self._bucket_count += 1
            if is_error:
                self._bucket_error_count += 1

    # ------------------------------------------------------------------ #
    # Background recalculation thread — call this in a daemon thread       #
    # ------------------------------------------------------------------ #

    def recalc_loop(self):
        """Runs forever; recalculates baseline every recalc_seconds."""
        while True:
            time.sleep(self._recalc_seconds)
            self._flush_bucket()
            self._evict_old()
            mean, stddev = self._compute_effective("requests")
            err_mean, err_stddev = self._compute_effective("errors")
            with self._lock:
                self.effective_mean = mean
                self.effective_stddev = stddev
                self.effective_error_mean = err_mean
                self.effective_error_stddev = err_stddev
            logger.info(
                "[BASELINE] mean=%.2f stddev=%.2f err_mean=%.2f err_stddev=%.2f",
                mean, stddev, err_mean, err_stddev,
            )

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def _flush_bucket(self):
        """Move current second's count into the rolling windows."""
        bucket = self._current_bucket
        count = self._bucket_count
        err_count = self._bucket_error_count
        hour_key = self._hour_key(bucket)

        self._global_counts.append((bucket, count))
        self._global_error_counts.append((bucket, err_count))

        if hour_key not in self._hourly_slots:
            self._hourly_slots[hour_key] = deque()
            self._hourly_error_slots[hour_key] = deque()
        self._hourly_slots[hour_key].append(count)
        self._hourly_error_slots[hour_key].append(err_count)

    def _evict_old(self):
        """Remove entries older than the rolling window from global deques."""
        cutoff = int(time.time()) - self._window_seconds
        while self._global_counts and self._global_counts[0][0] < cutoff:
            self._global_counts.popleft()
        while self._global_error_counts and self._global_error_counts[0][0] < cutoff:
            self._global_error_counts.popleft()

        # Keep only last 2 hourly slots to bound memory
        if len(self._hourly_slots) > 2:
            oldest = sorted(self._hourly_slots.keys())[0]
            del self._hourly_slots[oldest]
            del self._hourly_error_slots[oldest]

    def _compute_effective(self, kind: str) -> Tuple[float, float]:
        """
        Return (mean, stddev) preferring the current hour's slot when it
        has enough samples, falling back to the full rolling window.
        """
        now = time.time()
        hour_key = self._hour_key(int(now))

        if kind == "requests":
            hourly = self._hourly_slots.get(hour_key, deque())
            global_counts = [c for _, c in self._global_counts]
        else:
            hourly = self._hourly_error_slots.get(hour_key, deque())
            global_counts = [c for _, c in self._global_error_counts]

        # Prefer current hour if it has sufficient data
        samples = list(hourly) if len(hourly) >= self._min_samples else global_counts

        if len(samples) < 2:
            return (0.0, 1.0)

        mean = sum(samples) / len(samples)
        variance = sum((x - mean) ** 2 for x in samples) / len(samples)
        stddev = max(math.sqrt(variance), 0.1)  # floor to avoid division by zero
        return (mean, stddev)

    @staticmethod
    def _hour_key(ts: int) -> tuple:
        import time as _time
        t = _time.gmtime(ts)
        return (t.tm_year, t.tm_mon, t.tm_mday, t.tm_hour)

    def snapshot(self) -> dict:
        """Return a copy of current baseline values for the dashboard."""
        with self._lock:
            return {
                "effective_mean": round(self.effective_mean, 3),
                "effective_stddev": round(self.effective_stddev, 3),
                "effective_error_mean": round(self.effective_error_mean, 3),
                "effective_error_stddev": round(self.effective_error_stddev, 3),
                "global_window_size": len(self._global_counts),
                "hourly_slots": list(self._hourly_slots.keys()),
            }
