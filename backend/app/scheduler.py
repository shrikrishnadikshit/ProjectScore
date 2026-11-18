"""Continuous monitoring: rescans every monitored company daily by default (BRS TPRM-020, NFR-003).

Each organisation can choose 1, 3 or 7 days; a company is rescanned on the shortest cadence any
organisation monitoring it has chosen.

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

RESCAN_AFTER = timedelta(days=int(os.getenv("RESCAN_DAYS", "1")))
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
    from .workflow import prefs

    org_days = {}
    cadence: dict[int, int] = {}
    for entity_id, org_id in session.execute(select(PortfolioItem.entity_id, PortfolioItem.org_id)).all():
        if org_id not in org_days:
            org_days[org_id] = prefs(session, org_id)["rescan_days"]
        cadence[entity_id] = min(cadence.get(entity_id, 99), org_days[org_id])
    due = []
    for entity_id, last in rows:
        last = last if last.tzinfo else last.replace(tzinfo=timezone.utc)
        # a little slack so a daily rescan does not drift later by the scheduler's check interval each day
        if last <= now - timedelta(days=cadence.get(entity_id, RESCAN_AFTER.days)) + timedelta(minutes=30):
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
        try:
            from .certificates import send_reminders

            session = db.SessionLocal()
            try:
                send_reminders(session)
            finally:
                session.close()
        except Exception:
            logger.exception("certificate reminders failed")
        try:
            from .certin import refresh_async

            refresh_async()
        except Exception:
            logger.exception("CERT-In refresh failed")
        try:
            from .advisories import refresh_async as cisa_refresh

            cisa_refresh()
        except Exception:
            logger.exception("CISA advisory refresh failed")
        try:
            from .onboarding import review_reminders
            from .workflow import expire_acceptances, overdue_alerts

            session = db.SessionLocal()
            try:
                review_reminders(session)
                overdue_alerts(session)
                expire_acceptances(session)
                from .vendorprofile import contract_reminders

                contract_reminders(session)
                from .privacy import apply_retention

                apply_retention(session)
            finally:
                session.close()
        except Exception:
            logger.exception("reassessment reminders failed")


def start() -> None:
    if os.getenv("SCHEDULER_ENABLED", "true").lower() == "false":
        return
    _stop.clear()
    threading.Thread(target=_loop, name="rescan-scheduler", daemon=True).start()


def stop() -> None:
    _stop.set()
