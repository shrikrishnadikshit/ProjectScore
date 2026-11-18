"""Sentiment scoring. Uses VADER (MIT licence, runs locally, no data leaves the server).

VADER is built for English social media text. Text in other languages gets a neutral score unless a
star rating is available, so the dashboard does not invent opinions it cannot read.
"""

from __future__ import annotations

import re

try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer

    _vader = SentimentIntensityAnalyzer()
except ImportError:  # pragma: no cover - the dependency is in requirements.txt
    _vader = None

# Words that matter more for a business than in everyday speech. VADER's lexicon misses most of them.
BUSINESS_TERMS = {
    "scam": -3.0, "fraud": -3.2, "fraudulent": -3.2, "refund": -1.2, "lawsuit": -2.5, "sued": -2.4,
    "boycott": -2.6, "outage": -2.2, "breach": -2.6, "hacked": -2.8, "leak": -2.0, "leaked": -2.2,
    "layoffs": -2.0, "recall": -1.8, "ripoff": -2.8, "rip-off": -2.8, "overcharged": -2.4,
    "unresponsive": -2.0, "rude": -2.2, "delay": -1.2, "delayed": -1.4, "spam": -2.0, "fake": -2.2,
    "crash": -2.0, "crashes": -2.0, "crashing": -2.0, "bug": -1.2, "buggy": -2.0, "unusable": -2.6,
    "fined": -2.2, "penalty": -1.8, "probe": -1.4, "investigation": -1.2, "downtime": -2.0,
    "award": 2.2, "awarded": 2.2, "recommend": 2.0, "recommended": 2.0, "reliable": 2.0,
    "seamless": 2.0, "helpful": 2.0, "partnership": 1.2, "milestone": 1.6, "record": 0.6,
}
if _vader is not None:
    _vader.lexicon.update(BUSINESS_TERMS)

POSITIVE_AT = 0.2
NEGATIVE_AT = -0.2
_ASCII_LETTERS = re.compile(r"[A-Za-z]")
_LETTERS = re.compile(r"[^\W\d_]", re.UNICODE)


def looks_english(text: str) -> bool:
    letters = _LETTERS.findall(text or "")
    if len(letters) < 3:
        return False
    return sum(1 for c in letters if _ASCII_LETTERS.match(c)) / len(letters) > 0.8


def text_score(text: str) -> float | None:
    """-1..+1, or None when the text cannot be read (empty, not English)."""
    if not text or _vader is None or not looks_english(text):
        return None
    return round(_vader.polarity_scores(text[:5000])["compound"], 3)


def stars_score(rating: int | None) -> float | None:
    if rating is None:
        return None
    return {1: -0.9, 2: -0.6, 3: 0.0, 4: 0.6, 5: 0.9}.get(int(rating))


def score(text: str | None, rating: int | None = None) -> tuple[float, str]:
    """Combined score and label. A star rating, when present, outweighs the words (people are often polite
    in a one-star review), so it gets 70 percent of the weight."""
    t, s = text_score(text or ""), stars_score(rating)
    if t is not None and s is not None:
        value = 0.7 * s + 0.3 * t
    else:
        value = s if s is not None else t if t is not None else 0.0
    value = round(max(-1.0, min(1.0, value)), 3)
    return value, label(value)


def label(value: float) -> str:
    return "positive" if value >= POSITIVE_AT else "negative" if value <= NEGATIVE_AT else "neutral"
