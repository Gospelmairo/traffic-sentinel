"""
Structured audit logger.

Writes one line per event to the audit log file:
  [timestamp] ACTION ip | condition | rate | baseline | duration
"""

import os
import time
import threading
import logging

logger = logging.getLogger(__name__)


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuditLogger:
    def __init__(self, log_path: str):
        self._path = log_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def _write(self, line: str):
        with self._lock:
            try:
                with open(self._path, "a") as fh:
                    fh.write(line + "\n")
            except Exception as exc:
                logger.error("Audit log write failed: %s", exc)

    def log_ban(self, ip: str, condition: str, rate: float, baseline: float, duration: int):
        label = f"{duration}s" if duration != -1 else "permanent"
        self._write(
            f"[{_ts()}] BAN {ip} | {condition} | rate={rate:.2f} | baseline={baseline:.2f} | duration={label}"
        )

    def log_unban(self, ip: str):
        self._write(f"[{_ts()}] UNBAN {ip} | auto-release")

    def log_global_anomaly(self, condition: str, rate: float, baseline: float):
        self._write(
            f"[{_ts()}] GLOBAL_ANOMALY | {condition} | rate={rate:.2f} | baseline={baseline:.2f}"
        )

    def log_baseline_recalc(self, mean: float, stddev: float):
        self._write(
            f"[{_ts()}] BASELINE_RECALC | mean={mean:.4f} | stddev={stddev:.4f}"
        )

    def tail(self, n: int = 50) -> list:
        """Return last n lines of audit log."""
        try:
            with open(self._path, "r") as fh:
                lines = fh.readlines()
            return [l.strip() for l in lines[-n:]]
        except FileNotFoundError:
            return []
