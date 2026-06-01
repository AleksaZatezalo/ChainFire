"""
Background scheduler — checks every 60 seconds for due ScheduledScans
and fires them as regular Scan records.
"""
from __future__ import annotations

import logging
import threading
import time
from datetime import timedelta

from django.db import connection
from django.utils import timezone

logger = logging.getLogger(__name__)

_started = False
_lock = threading.Lock()


def start_scheduler() -> None:
    global _started
    with _lock:
        if _started:
            return
        _started = True

    thread = threading.Thread(
        target=_loop, daemon=True, name="chainfire-scheduler"
    )
    thread.start()
    logger.info("ChainFire scheduler started")


def _loop() -> None:
    while True:
        time.sleep(60)
        try:
            _fire_due()
        except Exception as exc:  # noqa: BLE001
            logger.exception("Scheduler error: %s", exc)
        finally:
            connection.close()


def _fire_due() -> None:
    from scanner.models import Scan, ScheduledScan
    from .scan_runner import start_scan

    now = timezone.now()
    due = ScheduledScan.objects.filter(enabled=True, next_run__lte=now)

    for sched in due:
        try:
            scan = Scan.objects.create(
                label=f"{sched.label or 'Scheduled'} ({sched.get_interval_display()})",
                target_url=sched.target_url,
                source_path=sched.source_path,
                scan_mode=sched.scan_mode,
                semgrep_rule=sched.semgrep_rule,
                nuclei_template=sched.nuclei_template,
                wordlist=sched.wordlist,
                min_severity=sched.min_severity,
            )
            start_scan(str(scan.id))

            sched.last_run = now
            sched.next_run = now + timedelta(
                seconds=ScheduledScan.INTERVAL_SECONDS[sched.interval]
            )
            sched.save(update_fields=["last_run", "next_run"])
            logger.info("Fired scheduled scan %s → scan %s", sched.id, scan.id)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to fire scheduled scan %s: %s", sched.id, exc)
