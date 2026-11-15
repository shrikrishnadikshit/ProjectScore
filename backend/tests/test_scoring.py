from datetime import datetime, timedelta, timezone

import pytest

from app.scoring import ScoringFinding, compute_score, grade_for

NOW = datetime(2026, 12, 1, tzinfo=timezone.utc)


def f(factor, severity, **kw):
    return ScoringFinding(risk_factor=factor, severity=severity, asset_value="example.com", **kw)


def test_clean_scan_scores_900():
    result = compute_score([], {"email_security": 1, "tls": 2}, now=NOW)
    assert result["overall"] == 900
    assert result["grade"] == "A"


def test_findings_lower_score_and_are_traced():
    result = compute_score([f("email_security", "high", code="dmarc_missing")], {"email_security": 1, "tls": 1}, now=NOW)
    assert result["overall"] < 900
    assert result["factors"]["tls"]["score"] == 100
    assert result["trace"]["contributions"][0]["code"] == "dmarc_missing"


def test_size_normalisation_softens_penalty_for_larger_estates():
    findings = [f("tls", "medium")]
    small = compute_score(findings, {"tls": 1}, now=NOW)["factors"]["tls"]["score"]
    large = compute_score(findings, {"tls": 16}, now=NOW)["factors"]["tls"]["score"]
    assert large > small


def test_remediated_findings_decay():
    recent = f("tls", "high", status="remediated", last_seen=NOW - timedelta(days=1))
    old = f("tls", "high", status="remediated", last_seen=NOW - timedelta(days=120))
    assert compute_score([old], {"tls": 1}, now=NOW)["overall"] > compute_score([recent], {"tls": 1}, now=NOW)["overall"]


def test_false_positive_ignored():
    assert compute_score([f("tls", "critical", status="false_positive")], {"tls": 1}, now=NOW)["overall"] == 900


def test_compromise_gate_caps_score():
    result = compute_score([f("compromise", "high")], {"compromise": 1, "tls": 50, "email_security": 1}, now=NOW)
    assert result["overall"] <= 640
    assert result["trace"]["gates"][0]["gate"] == "active_compromise"


def test_unassessed_factors_are_excluded():
    result = compute_score([f("compromise", "critical")], {"tls": 1}, now=NOW)
    assert "compromise" not in result["factors"]
    assert result["coverage"] == 0.08


def test_requires_some_coverage():
    with pytest.raises(ValueError):
        compute_score([], {}, now=NOW)


@pytest.mark.parametrize("score,grade", [(900, "A"), (800, "A"), (799, "B"), (650, "C"), (500, "D"), (300, "F")])
def test_grade_bands(score, grade):
    assert grade_for(score) == grade
