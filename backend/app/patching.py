"""Patching speed (BitSight-style "patching cadence"): how quickly a company fixes vulnerabilities.

Measured from our own scan history: when a vulnerability finding was first seen and when a later scan
saw it gone. Serious vulnerabilities left open for more than SLOW_DAYS also add a finding of their own.
"""

from __future__ import annotations

from datetime import datetime, timezone
from statistics import median

from .collectors import RawFinding

SLOW_DAYS = 60
PATCH_FACTORS = ("vulnerability",)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def slow_patch_findings(previous_open: list, current_keys: set[tuple[str, str]], now: datetime) -> list[RawFinding]:
    """Serious vulnerabilities seen again in this scan that have been open longer than SLOW_DAYS."""
    out = []
    for f in previous_open:
        if (f.risk_factor not in PATCH_FACTORS or f.severity not in ("critical", "high")
                or f.code.startswith("slow_patch_") or (f.code, f.asset_value) not in current_keys):
            continue
        days = (now - _aware(f.first_seen)).days
        if days > SLOW_DAYS:
            out.append(RawFinding("vulnerability", f"slow_patch_{f.code}"[:100],
                                  f"Serious vulnerability left unpatched for over {SLOW_DAYS} days: {f.title}",
                                  "medium", f.asset_value, {"days_open": days, "first_seen": _aware(f.first_seen).isoformat()}))
    return out


def summary(findings: list, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    vulns = [f for f in findings if f.risk_factor in PATCH_FACTORS and not f.code.startswith("slow_patch_")]
    fixed = [(_aware(f.last_seen) - _aware(f.first_seen)).days for f in vulns if f.status == "remediated"]
    open_ages = [(now - _aware(f.first_seen)).days for f in vulns if f.status == "open"]
    return {"fixed": len(fixed), "median_days_to_fix": round(median(fixed)) if fixed else None,
            "open": len(open_ages), "open_over_30_days": sum(a > 30 for a in open_ages),
            "oldest_open_days": max(open_ages) if open_ages else None}
