"""
Tails the Nginx JSON access log line by line and dispatches each parsed
entry to registered callbacks.
"""

import json
import time
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def tail_log(log_file: str, callback):
    """
    Blocks forever, reading new lines from log_file as they appear.
    Each parsed JSON entry is passed to callback(entry).

    entry keys: source_ip, timestamp, method, path, status, response_size
    """
    path = Path(log_file)

    # Wait until the log file exists (Nginx may not have started yet)
    while not path.exists():
        logger.info("Waiting for log file: %s", log_file)
        time.sleep(2)

    logger.info("Tailing log file: %s", log_file)

    with open(log_file, "r") as fh:
        # Jump to end so we only process new lines
        fh.seek(0, os.SEEK_END)

        while True:
            line = fh.readline()
            if not line:
                time.sleep(0.01)
                continue

            line = line.strip()
            if not line:
                continue

            try:
                entry = json.loads(line)
                callback(entry)
            except json.JSONDecodeError:
                logger.debug("Non-JSON log line skipped: %s", line[:80])
            except Exception as exc:
                logger.warning("Error processing log line: %s", exc)
