"""Tests for the rule catalog, finding factory and risk engine."""

from __future__ import annotations

import pytest

from irkit.config import Limits
from irkit.findings import FindingsFactory
from irkit.models import Confidence, Severity
from irkit.risk import (
    CONFIDENCE_FACTORS,
    FORMULA,
    SEVERITY_WEIGHTS,
    RiskEngine,
    rating_for,
)
from irkit.rules import RULES, get_rule, rules_by_category


def make_finding(
    factory: FindingsFactory,
    rule_id: str = "USER_UID0_NONROOT",
    *,
    confidence: Confidence | None = None,
    severity: Severity | None = None,
    collector: str = "users",
):
    return factory.create(
        rule_id,
        collector=collector,
        description="observed fact",
        details={"path": "/etc/passwd"},
        confidence=confidence,
        severity=severity,
    )


def test_severity_rank_and_aliases() -> None:
    assert Severity.from_str("info") is Severity.INFO
    assert Severity.from_str("MODERATE") is Severity.MEDIUM
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
    assert Severity.highest([Severity.LOW, Severity.HIGH]) is Severity.HIGH
    assert Severity.highest([]) is Severity.INFO
    with pytest.raises(ValueError):
        Severity.from_str("catastrophic")


def test_rule_catalog_is_consistent() -> None:
    assert RULES
    for rule in RULES.values():
        assert rule.rule_id
        assert rule.title
        assert rule.category
        assert rule.why
        assert rule.false_positives
        assert rule.remediation
    assert "USER_UID0_NONROOT" in RULES
    assert "IOC_MATCH" in RULES
    assert get_rule("USER_UID0_NONROOT").severity is Severity.CRITICAL
    with pytest.raises(KeyError):
        get_rule("DOES_NOT_EXIST")
    grouped = rules_by_category()
    assert "user" in grouped
    assert any(rule.rule_id == "USER_UID0_NONROOT" for rule in grouped["user"])


def test_finding_uses_catalog_context_and_sequential_ids() -> None:
    factory = FindingsFactory(Limits())
    first = make_finding(factory)
    second = make_finding(factory, "USER_DUPLICATE_UID")
    assert first is not None and second is not None
    assert first.finding_id == "F-0001"
    assert second.finding_id == "F-0002"
    assert first.title == get_rule("USER_UID0_NONROOT").title
    assert first.why == get_rule("USER_UID0_NONROOT").why
    assert first.remediation == get_rule("USER_UID0_NONROOT").remediation
    assert first.false_positives == list(get_rule("USER_UID0_NONROOT").false_positives)
    assert first.details == {"path": "/etc/passwd"}


def test_finding_severity_override_and_confidence_defaults() -> None:
    factory = FindingsFactory(Limits())
    overridden = make_finding(factory, severity=Severity.LOW, confidence=Confidence.HIGH)
    assert overridden is not None
    assert overridden.severity is Severity.LOW
    assert overridden.confidence is Confidence.HIGH
    defaulted = make_finding(factory, "USER_EMPTY_PASSWORD")
    assert defaulted is not None
    assert defaulted.confidence is get_rule("USER_EMPTY_PASSWORD").confidence


def test_finding_cap_and_suppression_summary() -> None:
    factory = FindingsFactory(Limits(max_findings_per_rule=2))
    assert make_finding(factory) is not None
    assert make_finding(factory) is not None
    assert make_finding(factory) is None
    assert factory.suppressed_summary() == {"USER_UID0_NONROOT": 1}


def test_finding_details_are_bounded_and_json_safe() -> None:
    factory = FindingsFactory(Limits(max_json_details_chars=200))
    finding = factory.create(
        "USER_UID0_NONROOT",
        collector="users",
        description="fact",
        details={"long": "x" * 500, "nested": {"path": "/etc/passwd"}, "number": 3},
    )
    assert finding is not None
    assert finding.details["number"] == 3
    assert finding.details["nested"]["path"] == "/etc/passwd"
    assert len(finding.details["long"]) <= 225
    assert finding.details["long"].endswith("[truncated 300 chars]")


def test_risk_score_weights_and_confidence() -> None:
    factory = FindingsFactory(Limits())
    high = make_finding(factory, "USER_UID0_NONROOT", confidence=Confidence.HIGH)
    medium = make_finding(factory, "USER_RECENT_ACCOUNT", confidence=Confidence.MEDIUM)
    assert high is not None and medium is not None
    assessment = RiskEngine().assess([high, medium])
    expected = SEVERITY_WEIGHTS[Severity.CRITICAL] * CONFIDENCE_FACTORS[Confidence.HIGH]
    expected += SEVERITY_WEIGHTS[Severity.MEDIUM] * CONFIDENCE_FACTORS[Confidence.MEDIUM]
    assert assessment.weighted_score == pytest.approx(expected)
    assert assessment.score == round(expected)
    assert assessment.overall_severity is Severity.CRITICAL
    assert assessment.counts["critical"] == 1
    assert assessment.counts["medium"] == 1
    assert assessment.counts["low"] == 0
    assert assessment.formula == FORMULA


def test_risk_score_is_capped_at_100() -> None:
    factory = FindingsFactory(Limits(max_findings_per_rule=1000))
    findings = [make_finding(factory, confidence=Confidence.HIGH) for _ in range(10)]
    assessment = RiskEngine().assess(findings)
    assert assessment.score == 100
    assert assessment.rating == "Severe"
    assert assessment.weighted_score > 100


def test_empty_risk_assessment() -> None:
    assessment = RiskEngine().assess([])
    assert assessment.score == 0
    assert assessment.rating == "Minimal"
    assert assessment.overall_severity is Severity.INFO
    assert assessment.total_findings == 0
    assert all(value == 0 for value in assessment.counts.values())


@pytest.mark.parametrize(
    ("score", "rating"),
    [(0, "Minimal"), (1, "Low"), (14, "Low"), (15, "Elevated"), (39, "Elevated"), (40, "High"), (69, "High"), (70, "Severe"), (100, "Severe")],
)
def test_rating_boundaries(score: int, rating: str) -> None:
    assert rating_for(score) == rating
