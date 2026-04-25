"""
IP blocker using iptables DROP rules.

Tracks banned IPs and their offense counts so the unbanner can apply
the correct backoff schedule.
"""

import subprocess
import threading
import time
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Unban schedule in seconds: index = offense number (0-based)
# Index 3+ means permanent (duration = -1)
UNBAN_SCHEDULE = [600, 1800, 7200]


class IPBlocker:
    def __init__(self):
        self._lock = threading.Lock()
        # ip -> {banned_at, unban_at, offense_count, duration}
        self._banned: Dict[str, dict] = {}

    def ban(self, ip: str) -> int:
        """
        Add iptables DROP rule for ip.
        Returns ban duration in seconds (-1 = permanent).
        """
        with self._lock:
            offense = self._banned.get(ip, {}).get("offense_count", 0)
            if offense < len(UNBAN_SCHEDULE):
                duration = UNBAN_SCHEDULE[offense]
            else:
                duration = -1  # permanent

            now = time.time()
            unban_at = (now + duration) if duration != -1 else None

            self._banned[ip] = {
                "banned_at": now,
                "unban_at": unban_at,
                "offense_count": offense + 1,
                "duration": duration,
            }

        self._iptables("A", ip)
        label = f"{duration}s" if duration != -1 else "permanent"
        logger.warning("BANNED %s for %s (offense #%d)", ip, label, offense + 1)
        return duration

    def unban(self, ip: str):
        """Remove iptables DROP rule for ip."""
        with self._lock:
            if ip not in self._banned:
                return
            # Keep offense count for backoff, but clear active ban
            self._banned[ip]["unban_at"] = None

        self._iptables("D", ip)
        logger.info("UNBANNED %s", ip)

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            info = self._banned.get(ip)
            if not info:
                return False
            unban_at = info.get("unban_at")
            # unban_at == None means permanent ban
            if unban_at is None and info["offense_count"] > 0:
                return True
            if unban_at and time.time() < unban_at:
                return True
            return False

    def due_for_unban(self) -> list:
        """Return list of IPs whose ban has expired (not permanent)."""
        now = time.time()
        due = []
        with self._lock:
            for ip, info in self._banned.items():
                unban_at = info.get("unban_at")
                if unban_at is not None and now >= unban_at:
                    due.append(ip)
        return due

    def banned_snapshot(self) -> list:
        now = time.time()
        result = []
        with self._lock:
            for ip, info in self._banned.items():
                unban_at = info.get("unban_at")
                if unban_at is not None and now < unban_at:
                    result.append({
                        "ip": ip,
                        "banned_at": info["banned_at"],
                        "unban_at": unban_at,
                        "duration": info["duration"],
                        "offense_count": info["offense_count"],
                    })
                elif unban_at is None and info["offense_count"] > 0:
                    result.append({
                        "ip": ip,
                        "banned_at": info["banned_at"],
                        "unban_at": None,
                        "duration": -1,
                        "offense_count": info["offense_count"],
                    })
        return result

    @staticmethod
    def _iptables(action: str, ip: str):
        """
        action: 'A' (append/ban) or 'D' (delete/unban)
        """
        cmd = ["iptables", f"-{action}", "INPUT", "-s", ip, "-j", "DROP"]
        try:
            subprocess.run(cmd, check=True, capture_output=True)
        except subprocess.CalledProcessError as exc:
            logger.error("iptables -%s %s failed: %s", action, ip, exc.stderr.decode())
        except FileNotFoundError:
            logger.error("iptables not found — is this running as root?")
