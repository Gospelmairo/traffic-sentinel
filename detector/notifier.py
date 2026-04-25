"""
Slack notifier.

Sends formatted messages to a Slack incoming webhook for ban, unban,
and global anomaly events.
"""

import time
import logging
import requests

logger = logging.getLogger(__name__)


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self._url = webhook_url
        self._enabled = bool(webhook_url and webhook_url != "YOUR_SLACK_WEBHOOK_URL")

    def ban_alert(self, ip: str, condition: str, rate: float, baseline: float, duration: int):
        label = f"{duration}s" if duration != -1 else "permanent"
        text = (
            f":rotating_light: *IP BANNED* `{ip}`\n"
            f">Condition: {condition}\n"
            f">Current rate: `{rate:.2f}` req/s\n"
            f">Baseline mean: `{baseline:.2f}` req/s\n"
            f">Ban duration: `{label}`\n"
            f">Timestamp: `{_ts()}`"
        )
        self._send(text)

    def unban_alert(self, ip: str):
        text = (
            f":white_check_mark: *IP UNBANNED* `{ip}`\n"
            f">Timestamp: `{_ts()}`"
        )
        self._send(text)

    def global_alert(self, condition: str, rate: float, baseline: float):
        text = (
            f":warning: *GLOBAL TRAFFIC ANOMALY*\n"
            f">Condition: {condition}\n"
            f">Current global rate: `{rate:.2f}` req/s\n"
            f">Baseline mean: `{baseline:.2f}` req/s\n"
            f">Timestamp: `{_ts()}`"
        )
        self._send(text)

    def _send(self, text: str):
        if not self._enabled:
            logger.info("[SLACK DISABLED] %s", text)
            return
        try:
            resp = requests.post(
                self._url,
                json={"text": text},
                timeout=5,
            )
            resp.raise_for_status()
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
