"""Continuous monitoring: rescans every monitored company once a week (BRS continuous monitoring).

Runs as a background thread inside the web server. Suitable for a single server instance; with
several instances, move this to a dedicated worker or cron job so scans are not duplicated.
"""

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select

from . import db
from .models import Entity, PortfolioItem, Score
from .scan import NothingAssessed, scan_entity

logger = logging.getLogger("projectscore.scheduler")

RESCAN_AFTER = timedelta(days=int(os.getenv("RESCAN_DAYS", "7")))
CHECK_EVERY_SECONDS = int(os.getenv("SCHEDULER_INTERVAL_SECONDS", "3600"))
PAUSE_BETWEEN_SCANS_SECONDS = 5

_stop = threading.Event()


def due_entity_ids(session, now: datetime | None = None) -> list[int]:
    """Monitored entities whose latest score is older than RESCAN_AFTER, oldest first.
    Entities never scanned are left to the user-triggered first scan."""
    now = now or datetime.now(timezone.utc)
    latest = (select(Score.entity_id, func.max(Score.created_at).label("last"))
              .group_by(Score.entity_id).subquery())
    monitored = select(PortfolioItem.entity_id).distinct()
    rows = session.execute(
        select(Entity.id, latest.c.last).join(latest, latest.c.entity_id == Entity.id)
        .where(Entity.id.in_(monitored)).order_by(latest.c.last)).all()
    cutoff = now - RESCAN_AFTER
    due = []
    for entity_id, last in rows:
        last = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
        if last <= cutoff:
            due.append(entity_id)
    return due


def run_due_scans() -> int:
    session = db.SessionLocal()
    done = 0
    try:
        for entity_id in due_entity_ids(session):
            if _stop.is_set():
                break
            try:
                scan_entity(session, session.get(Entity, entity_id))
                done += 1
            except NothingAssessed as exc:
                logger.warning("scheduled scan skipped: %s", exc)
            except Exception:
                session.rollback()
                logger.exception("scheduled scan failed for entity %s", entity_id)
            time.sleep(PAUSE_BETWEEN_SCANS_SECONDS)
    finally:
        session.close()
    if done:
        logger.info("scheduled rescans completed: %d", done)
    return done


def _loop() -> None:
    while not _stop.wait(CHECK_EVERY_SECONDS):
        try:
            run_due_scans()
        except Exception:
            logger.exception("scheduler cycle failed")


def start() -> None:
    if os.getenv("SCHEDULER_ENABLED", "true").lower() == "false":
        return
    _stop.clear()
    threading.Thread(target=_loop, name="rescan-scheduler", daemon=True).start()


def stop() -> None:
    _stop.set()
