"""Rating engine v1, implementing BRS Section 7.

Every point deducted is traceable: `compute_score` returns a trace listing each
finding's contribution to its factor penalty.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone

MODEL_VERSION = "1.0.0"

# BRS 7.3 indicative weights (starting hypothesis, to be calibrated).
FACTOR_WEIGHTS: dict[str, float] = {
    "compromise": 0.20,
    "vulnerability": 0.18,
    "network_exposure": 0.12,
    "identity": 0.10,
    "email_security": 0.08,
    "tls": 0.08,
    "web_security": 0.08,
    "dns_health": 0.06,
    "breach_history": 0.06,
    "brand": 0.04,
}

# BRS 7.4 severity points.
SEVERITY_POINTS = {"critical": 10, "high": 7, "medium": 4, "low": 1, "info": 0}

# BRS 7.4 half-lives in days. Open findings are "last seen" now, so they do not decay.
HALF_LIFE_DAYS = {"compromise": 60, "breach_history": 365}
DEFAULT_HALF_LIFE_DAYS = 30

SIZE_ALPHA = 0.5
# Calibration constant for the penalty-to-score curve: score = 100 * exp(-penalty / K).
# A single high finding on one asset gives about 42 (grade F for that factor); to be calibrated
# by back-testing against incident outcomes (BRS 7.3).
CURVE_K = 8.0

# BRS 7.4 gates: severe issues cap the overall score.
GATES = [
    ("active_compromise", 640, lambda f: f.risk_factor == "compromise" and f.severity in ("critical", "high")),
    ("kev_critical_exposure", 700, lambda f: f.risk_factor == "vulnerability" and f.severity == "critical"
     and bool(f.evidence.get("kev"))),
]

GRADE_BANDS = [(800, "A"), (700, "B"), (600, "C"), (500, "D"), (300, "F")]
FACTOR_GRADE_BANDS = [(90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F")]


@dataclass
class ScoringFinding:
    risk_factor: str
    severity: str
    asset_value: str
    code: str = ""
    detection_confidence: float = 1.0
    attribution_confidence: float = 1.0
    status: str = "open"
    last_seen: datetime | None = None
    evidence: dict = field(default_factory=dict)


def grade_for(score: int) -> str:
    for floor, grade in GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def factor_grade_for(score: float) -> str:
    for floor, grade in FACTOR_GRADE_BANDS:
        if score >= floor:
            return grade
    return "F"


def decay(finding: ScoringFinding, now: datetime) -> float:
    if finding.status == "open" or finding.last_seen is None:
        return 1.0
    last_seen = finding.last_seen if finding.last_seen.tzinfo else finding.last_seen.replace(tzinfo=timezone.utc)
    days = max((now - last_seen).total_seconds() / 86400, 0.0)
    half_life = HALF_LIFE_DAYS.get(finding.risk_factor, DEFAULT_HALF_LIFE_DAYS)
    return 0.5 ** (days / half_life)


def compute_score(
    findings: list[ScoringFinding],
    assets_per_factor: dict[str, int],
    now: datetime | None = None,
) -> dict:
    """Compute the overall score, factor scores and a calculation trace.

    `assets_per_factor` lists the factors that were actually assessed and how many
    assets each covered. Factors that were not assessed are excluded and the
    remaining weights are renormalised, so a partial scan is not mistaken for a
    clean one; the result reports coverage explicitly.
    """
    now = now or datetime.now(timezone.utc)
    assessed = {f: n for f, n in assets_per_factor.items() if f in FACTOR_WEIGHTS and n > 0}
    if not assessed:
        raise ValueError("No risk factors were assessed")

    factors: dict[str, dict] = {}
    trace: list[dict] = []
    for factor, asset_count in assessed.items():
        raw = 0.0
        for f in findings:
            if f.risk_factor != factor or f.status in ("false_positive",):
                continue
            s = SEVERITY_POINTS.get(f.severity, 0)
            c = f.detection_confidence * f.attribution_confidence
            d = decay(f, now)
            contribution = s * c * d
            if contribution == 0:
                continue
            raw += contribution
            trace.append({
                "factor": factor, "code": f.code, "asset": f.asset_value, "severity": f.severity,
                "S": s, "C": round(c, 3), "D": round(d, 3), "contribution": round(contribution, 3),
            })
        penalty = raw / (asset_count ** SIZE_ALPHA)
        score = 100.0 * math.exp(-penalty / CURVE_K)
        factors[factor] = {
            "score": round(score, 1), "grade": factor_grade_for(score),
            "penalty": round(penalty, 3), "assets": asset_count, "weight": FACTOR_WEIGHTS[factor],
        }

    total_weight = sum(FACTOR_WEIGHTS[f] for f in factors)
    weighted = sum(FACTOR_WEIGHTS[f] / total_weight * v["score"] for f, v in factors.items())
    overall = round(300 + 6 * weighted)

    gates_applied = []
    for name, cap, predicate in GATES:
        if any(predicate(f) and f.status == "open" for f in findings) and overall > cap:
            overall = cap
            gates_applied.append({"gate": name, "cap": cap})

    return {
        "overall": overall,
        "grade": grade_for(overall),
        "model_version": MODEL_VERSION,
        "factors": factors,
        "coverage": round(total_weight, 2),
        "trace": {"contributions": trace, "gates": gates_applied},
    }
