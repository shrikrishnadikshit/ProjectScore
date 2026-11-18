"""Online reputation management: reviews, social and news mentions, sentiment, crisis alerts,
suggested replies, and tracking of what shows up when people search for the brand.

Switched off unless REPUTATION_MODULE=on, so it cannot affect the security ratings launch.
"""

from __future__ import annotations

import logging
import os
import threading
from datetime import timedelta


def enabled() -> bool:
    return os.environ.get("REPUTATION_MODULE", "off").lower() in ("on", "true", "1", "yes")


from . import models  # noqa: E402,F401  (registers the tables before create_all)
from .api import router  # noqa: E402

logger = logging.getLogger("projectscore.reputation")
_stop = threading.Event()


def poll_due() -> int:
    """Poll brands not checked within REPUTATION_POLL_MINUTES, take weekly search snapshots, purge old data."""
    from sqlalchemy import func, or_, select

    from .. import db
    from . import service, sources
    from .models import Brand, SearchSnapshot

    every = timedelta(minutes=int(os.environ.get("REPUTATION_POLL_MINUTES", "360")))
    search_every = timedelta(days=int(os.environ.get("REPUTATION_SEARCH_DAYS", "7")))
    session = db.SessionLocal()
    done = 0
    try:
        cutoff = service.now() - every
        ids = session.scalars(select(Brand.id).where(or_(Brand.last_polled_at.is_(None), Brand.last_polled_at <= cutoff))
                              .order_by(Brand.last_polled_at)).all()
        for bid in ids:
            if _stop.is_set():
                break
            try:
                service.poll_brand(session, session.get(Brand, bid))
                done += 1
            except Exception:
                session.rollback()
                logger.exception("reputation poll failed for brand %s", bid)
        if sources.search_available():
            for b in session.scalars(select(Brand)).all():
                last = session.scalar(select(func.max(SearchSnapshot.taken_at)).where(SearchSnapshot.brand_id == b.id))
                if last is None or service.now() - service.aware(last) >= search_every:
                    try:
                        service.take_search_snapshot(session, b)
                    except Exception:
                        session.rollback()
                        logger.exception("search snapshot failed for brand %s", b.id)
        service.purge_old(session)
    finally:
        session.close()
    return done


def _loop() -> None:
    interval = int(os.environ.get("REPUTATION_CHECK_SECONDS", "900"))
    while not _stop.wait(interval):
        try:
            poll_due()
        except Exception:
            logger.exception("reputation cycle failed")


def start() -> None:
    if not enabled() or os.getenv("SCHEDULER_ENABLED", "true").lower() == "false":
        return
    _stop.clear()
    threading.Thread(target=_loop, name="reputation-poller", daemon=True).start()


def stop() -> None:
    _stop.set()


__all__ = ["enabled", "router", "start", "stop", "poll_due"]
