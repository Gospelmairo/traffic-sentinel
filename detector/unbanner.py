"""
Auto-unban daemon.

Checks every 10 seconds for IPs whose ban duration has elapsed and
releases them.  Sends a Slack notification and writes an audit entry
on every unban.
"""

import time
import logging

logger = logging.getLogger(__name__)


class UnbanManager:
    def __init__(self, blocker, notifier, audit_logger, check_interval: int = 10):
        self._blocker = blocker
        self._notifier = notifier
        self._audit = audit_logger
        self._interval = check_interval

    def run(self):
        """Blocks forever — run in a daemon thread."""
        while True:
            time.sleep(self._interval)
            for ip in self._blocker.due_for_unban():
                try:
                    info = next(
                        (b for b in self._blocker.banned_snapshot() if b["ip"] == ip),
                        None,
                    )
                    self._blocker.unban(ip)
                    self._notifier.unban_alert(ip)
                    self._audit.log_unban(ip)
                    logger.info("Auto-unbanned %s", ip)
                except Exception as exc:
                    logger.error("Error unbanning %s: %s", ip, exc)
