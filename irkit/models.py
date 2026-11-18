"""Typed data models used across the toolkit.

The models are deliberately plain dataclasses so they serialise predictably to
JSON and remain easy to construct in tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable


class Severity(str, Enum):
    """Finding severity, ordered from least to most urgent."""

    INFO = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def from_str(cls, value: str) -> "Severity":
        normalised = value.strip().lower()
        aliases = {
            "info": cls.INFO,
            "informational": cls.INFO,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "moderate": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
            "crit": cls.CRITICAL,
        }
        try:
            return aliases[normalised]
        except KeyError as exc:
            raise ValueError(f"unknown severity: {value!r}") from exc

    @classmethod
    def highest(cls, severities: Iterable["Severity"]) -> "Severity":
        return max(severities, key=lambda item: item.rank, default=cls.INFO)


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Confidence(str, Enum):
    """Analyst confidence in a finding, used to weight the risk score."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class CollectorStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class EvidenceItem:
    """A single piece of preserved evidence (file, command output or API data).

    ``sha256`` is computed at collection time.  For files the original content
    is never copied or altered unless the operator explicitly opts in.
    """

    evidence_id: str
    collector: str
    kind: str  # file | command | api | data | directory
    source_path: str | None
    description: str
    collected_at: str
    sha256: str | None = None
    size: int | None = None
    mtime: str | None = None
    mode: str | None = None
    owner: str | None = None
    group: str | None = None
    command: str | None = None
    notes: str | None = None
    readable: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "collector": self.collector,
            "kind": self.kind,
            "source_path": self.source_path,
            "description": self.description,
            "collected_at": self.collected_at,
            "sha256": self.sha256,
            "size": self.size,
            "mtime": self.mtime,
            "mode": self.mode,
            "owner": self.owner,
            "group": self.group,
            "command": self.command,
            "notes": self.notes,
            "readable": self.readable,
        }


@dataclass
class Finding:
    """A rule-generated observation with analyst context."""

    finding_id: str
    rule_id: str
    title: str
    severity: Severity
    category: str
    description: str
    why: str
    false_positives: list[str]
    remediation: str
    confidence: Confidence
    evidence_refs: list[str]
    details: dict[str, Any]
    mitre: list[str]
    detected_at: str
    collector: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "severity_rank": self.severity.rank,
            "category": self.category,
            "description": self.description,
            "why": self.why,
            "false_positives": list(self.false_positives),
            "remediation": self.remediation,
            "confidence": self.confidence.value,
            "evidence_refs": list(self.evidence_refs),
            "details": self.details,
            "mitre": list(self.mitre),
            "detected_at": self.detected_at,
            "collector": self.collector,
        }


@dataclass
class CollectorResult:
    """Outcome of one collector, including non-fatal degradation details."""

    name: str
    description: str
    status: CollectorStatus
    started_at: str
    finished_at: str
    duration_ms: int
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    requires_root: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "status": self.status.value,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_ms": self.duration_ms,
            "requires_root": self.requires_root,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
            "finding_ids": [finding.finding_id for finding in self.findings],
            "evidence_ids": [item.evidence_id for item in self.evidence],
            "data": self.data,
        }


@dataclass
class RiskAssessment:
    """Aggregated risk derived from all findings."""

    score: int
    rating: str
    overall_severity: Severity
    counts: dict[str, int]
    total_findings: int
    weighted_score: float
    formula: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "rating": self.rating,
            "overall_severity": self.overall_severity.value,
            "counts": dict(self.counts),
            "total_findings": self.total_findings,
            "weighted_score": round(self.weighted_score, 2),
            "formula": self.formula,
        }
