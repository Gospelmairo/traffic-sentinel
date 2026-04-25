"""
Entry point for the HNG anomaly detection daemon.

Starts all subsystems in daemon threads:
  - Log monitor      (tails nginx JSON access log)
  - Baseline recalc  (every 60 s)
  - Auto-unbanner    (every 10 s)
  - Dashboard        (Flask on port 8080)

Usage:
  python main.py [--config /path/to/config.yaml]
"""

import argparse
import logging
import os
import sys
import threading
import time

import yaml

from audit import AuditLogger
from baseline import BaselineTracker
from blocker import IPBlocker
from dashboard import create_app
from detector import AnomalyDetector
from monitor import tail_log
from notifier import SlackNotifier
from unbanner import UnbanManager

# ------------------------------------------------------------------ #
# Logging setup                                                        #
# ------------------------------------------------------------------ #

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("main")


def load_config(path: str) -> dict:
    with open(path) as fh:
        return yaml.safe_load(fh)


def main():
    parser = argparse.ArgumentParser(description="HNG Anomaly Detection Daemon")
    parser.add_argument("--config", default="/app/config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    start_time = time.time()

    slack_url = cfg["slack"]["webhook_url"]
    log_file = cfg["logging"]["nginx_log"]
    audit_path = cfg["logging"]["audit_log"]
    det = cfg["detection"]
    dash_port = cfg["dashboard"]["port"]

    # ---- Subsystem setup ------------------------------------------- #

    notifier = SlackNotifier(slack_url)
    audit = AuditLogger(audit_path)
    blocker = IPBlocker()

    baseline = BaselineTracker(
        window_minutes=det["baseline_window_minutes"],
        recalc_seconds=det["baseline_recalc_seconds"],
        min_samples=det["min_samples_for_baseline"],
    )

    detector = AnomalyDetector(
        baseline=baseline,
        blocker=blocker,
        notifier=notifier,
        audit_logger=audit,
        window_seconds=det["window_seconds"],
        zscore_threshold=det["zscore_threshold"],
        rate_multiplier=det["rate_multiplier"],
        error_rate_multiplier=det["error_rate_multiplier"],
        error_tightening=det["error_tightening_factor"],
    )

    unbanner = UnbanManager(blocker, notifier, audit)

    app = create_app(detector, baseline, blocker, audit, start_time)

    # Instrument baseline recalc to write audit entries
    _orig_recalc = baseline.recalc_loop

    def _instrumented_recalc():
        import time as _time
        while True:
            _time.sleep(baseline._recalc_seconds)
            baseline._flush_bucket()
            baseline._evict_old()
            mean, stddev = baseline._compute_effective("requests")
            err_mean, err_stddev = baseline._compute_effective("errors")
            import threading as _t
            with baseline._lock:
                baseline.effective_mean = mean
                baseline.effective_stddev = stddev
                baseline.effective_error_mean = err_mean
                baseline.effective_error_stddev = err_stddev
            audit.log_baseline_recalc(mean, stddev)
            logger.info(
                "[BASELINE] mean=%.2f stddev=%.2f err_mean=%.2f err_stddev=%.2f",
                mean, stddev, err_mean, err_stddev,
            )

    # ---- Daemon threads -------------------------------------------- #

    threads = [
        threading.Thread(
            target=lambda: tail_log(log_file, detector.process),
            name="monitor",
            daemon=True,
        ),
        threading.Thread(
            target=_instrumented_recalc,
            name="baseline-recalc",
            daemon=True,
        ),
        threading.Thread(
            target=unbanner.run,
            name="unbanner",
            daemon=True,
        ),
        threading.Thread(
            target=lambda: app.run(host="0.0.0.0", port=dash_port, use_reloader=False),
            name="dashboard",
            daemon=True,
        ),
    ]

    for t in threads:
        logger.info("Starting thread: %s", t.name)
        t.start()

    logger.info("HNG Anomaly Detector running. Dashboard: http://0.0.0.0:%d", dash_port)

    # Keep main thread alive
    try:
        while True:
            time.sleep(10)
    except KeyboardInterrupt:
        logger.info("Shutting down.")


if __name__ == "__main__":
    main()
