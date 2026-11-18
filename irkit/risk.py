"""Deterministic risk scoring.

The score is intentionally simple and documented so an analyst can reproduce
it by hand.  It is an aggregation aid, not a verdict: severity roll-up uses the
single most severe finding, while the score reflects how many independent
indicators were observed and how confident the detections are.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Iterable

from irkit.models import Confidence, Finding, RiskAssessment, Severity

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.INFO: 0.0,
    Severity.LOW: 3.0,
    Severity.MEDIUM: 10.0,
    Severity.HIGH: 25.0,
    Severity.CRITICAL: 50.0,
}

CONFIDENCE_FACTORS: dict[Confidence, float] = {
    Confidence.LOW: 0.5,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}

FORMULA = (
    "score = min(100, sum(severity_weight * confidence_factor)); "
    "weights: informational=0, low=3, medium=10, high=25, critical=50; "
    "confidence factors: low=0.5, medium=0.75, high=1.0"
)


def rating_for(score: int) -> str:
    """Map a 0-100 score to an operator-facing rating."""
    if score <= 0:
        return "Minimal"
    if score < 15:
        return "Low"
    if score < 40:
        return "Elevated"
    if score < 70:
        return "High"
    return "Severe"


@dataclass
class RiskEngine:
    """Compute a risk assessment from a set of findings."""

    def assess(self, findings: Iterable[Finding]) -> RiskAssessment:
        items = list(findings)
        counts: Counter[str] = Counter(finding.severity.value for finding in items)
        for severity in Severity:
            counts.setdefault(severity.value, 0)

        weighted = sum(
            SEVERITY_WEIGHTS[finding.severity] * CONFIDENCE_FACTORS[finding.confidence] for finding in items
        )
        score = int(min(100.0, round(weighted)))
        overall = Severity.highest(finding.severity for finding in items)
        return RiskAssessment(
            score=score,
            rating=rating_for(score),
            overall_severity=overall,
            counts=dict(counts),
            total_findings=len(items),
            weighted_score=weighted,
            formula=FORMULA,
        )
