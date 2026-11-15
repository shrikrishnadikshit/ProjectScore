"""Organisation settings for global use: home country, display currency and the local cost of a breach."""

from __future__ import annotations

import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import auth, db
from .models import OrgSettings, User

router = APIRouter(prefix="/api")

CURRENCIES = ["INR", "USD", "EUR", "GBP", "AUD", "SGD", "AED", "SAR", "JPY", "CAD", "CHF"]
# Average total cost of a data breach, millions of US dollars, from the IBM Cost of a Data Breach Report 2024
# (country and region averages, rounded). Organisations can override the figure for their own market.
BREACH_COST_USD_M = {
    "US": 9.36, "CA": 5.13, "GB": 4.53, "DE": 5.31, "IT": 4.73, "FR": 4.17, "BE": 5.90, "NL": 5.90, "LU": 5.90,
    "SE": 4.25, "NO": 4.25, "DK": 4.25, "FI": 4.25, "JP": 4.19, "KR": 3.62, "AU": 2.78, "IN": 2.35, "BR": 1.36,
    "ZA": 1.32, "SA": 8.75, "AE": 8.75, "QA": 8.75, "KW": 8.75, "BH": 8.75, "OM": 8.75,
    "SG": 3.23, "MY": 3.23, "ID": 3.23, "TH": 3.23, "PH": 3.23, "VN": 3.23,
    "MX": 2.76, "AR": 2.76, "CL": 2.76, "CO": 2.76, "PE": 2.76,
}
GLOBAL_AVERAGE_USD_M = 4.88
BREACH_COST_SOURCE = "IBM Cost of a Data Breach Report 2024"
# Countries under comprehensive sanctions: ProjectScore should not be sold to organisations based there.
SANCTIONED = {"CU": "Cuba", "IR": "Iran", "KP": "North Korea", "SY": "Syria"}
DEFAULT_CURRENCY = {"IN": "INR", "US": "USD", "GB": "GBP", "AU": "AUD", "SG": "SGD", "AE": "AED", "SA": "SAR",
                    "JP": "JPY", "CA": "CAD", "CH": "CHF"}


def settings_for(session: Session, org_id: int) -> dict:
    row = session.scalars(select(OrgSettings).where(OrgSettings.org_id == org_id)).first()
    country = row.country if row else "IN"
    override = row.breach_cost_usd_m if row else None
    return {"country": country, "currency": row.currency if row else "INR",
            "breach_cost_usd_m": override if override else BREACH_COST_USD_M.get(country, GLOBAL_AVERAGE_USD_M),
            "breach_cost_overridden": bool(override),
            "breach_cost_source": "your organisation's own figure" if override else (
                f"{BREACH_COST_SOURCE}, {'country or regional' if country in BREACH_COST_USD_M else 'global'} average")}


class SettingsIn(BaseModel):
    country: str
    currency: str
    breach_cost_usd_m: float | None = None

    @field_validator("country")
    @classmethod
    def _country(cls, v):
        v = v.strip().upper()
        if not re.fullmatch(r"[A-Z]{2}", v):
            raise ValueError("use a two-letter country code, e.g. IN, US or GB")
        if v in SANCTIONED:
            raise ValueError(f"ProjectScore is not available to organisations in {SANCTIONED[v]}")
        return v

    @field_validator("currency")
    @classmethod
    def _currency(cls, v):
        if v not in CURRENCIES:
            raise ValueError("unsupported currency")
        return v

    @field_validator("breach_cost_usd_m")
    @classmethod
    def _cost(cls, v):
        if v is not None and not 0.01 <= v <= 1000:
            raise ValueError("the breach cost must be between 0.01 and 1,000 million US dollars")
        return v


@router.get("/org-settings")
def get_settings(user: User = Depends(auth.current_user), session: Session = Depends(db.get_session)) -> dict:
    return {**settings_for(session, user.org_id), "currencies": CURRENCIES}


@router.put("/org-settings")
def put_settings(body: SettingsIn, user: User = Depends(auth.require_admin), session: Session = Depends(db.get_session)) -> dict:
    row = session.scalars(select(OrgSettings).where(OrgSettings.org_id == user.org_id)).first() or OrgSettings(org_id=user.org_id)
    row.country, row.currency, row.breach_cost_usd_m = body.country, body.currency, body.breach_cost_usd_m
    row.updated_at = datetime.now(timezone.utc)
    session.add(row)
    session.commit()
    return get_settings(user, session)
