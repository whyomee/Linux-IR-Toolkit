"""Finding construction.

The factory assigns stable IDs, applies the rule catalog, bounds repetitive
detections and makes details JSON-safe.  Collectors provide only the factual
description and supporting details; everything interpretive comes from the
catalog.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from irkit.config import Limits
from irkit.models import Confidence, EvidenceItem, Finding, Severity
from irkit.rules import get_rule
from irkit.utils import iso_utc, truncate


def _jsonable(value: Any, max_string: int) -> Any:
    """Coerce a value into JSON-safe primitives with bounded string lengths."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, str):
        return truncate(value, max_string)
    if isinstance(value, dict):
        return {str(key): _jsonable(item, max_string) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(item, max_string) for item in value]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if hasattr(value, "isoformat"):
        try:
            return value.isoformat()
        except (TypeError, ValueError):
            return str(value)
    return str(value)


@dataclass
class FindingsFactory:
    """Create :class:`Finding` objects from the central rule catalog."""

    limits: Limits = field(default_factory=Limits)
    _counter: int = 0
    _per_rule: Counter[str] = field(default_factory=Counter)
    suppressed: Counter[str] = field(default_factory=Counter)

    def create(
        self,
        rule_id: str,
        *,
        collector: str,
        description: str,
        details: dict[str, Any] | None = None,
        evidence: Iterable[EvidenceItem | str] = (),
        confidence: Confidence | None = None,
        title: str | None = None,
        severity: Severity | None = None,
    ) -> Finding | None:
        """Build a finding, or return ``None`` when the per-rule cap is reached.

        ``description`` must state what was observed factually.  It should not
        contain conclusions beyond what the rule already provides.

        ``severity`` may only be supplied by the IOC analyser, where the
        analyst's indicator file carries an explicit severity.  All other
        collectors use the catalog severity so it cannot be silently altered.
        """
        rule = get_rule(rule_id)
        if self._per_rule[rule_id] >= self.limits.max_findings_per_rule:
            self.suppressed[rule_id] += 1
            return None
        self._per_rule[rule_id] += 1
        self._counter += 1

        refs: list[str] = []
        for item in evidence:
            if isinstance(item, EvidenceItem):
                refs.append(item.evidence_id)
            elif isinstance(item, str):
                refs.append(item)

        safe_details = _jsonable(details or {}, self.limits.max_json_details_chars)
        return Finding(
            finding_id=f"F-{self._counter:04d}",
            rule_id=rule.rule_id,
            title=title or rule.title,
            severity=severity or rule.severity,
            category=rule.category,
            description=description,
            why=rule.why,
            false_positives=list(rule.false_positives),
            remediation=rule.remediation,
            confidence=confidence or rule.confidence,
            evidence_refs=refs,
            details=safe_details if isinstance(safe_details, dict) else {"value": safe_details},
            mitre=list(rule.mitre),
            detected_at=iso_utc(),
            collector=collector,
        )

    def suppressed_summary(self) -> dict[str, int]:
        return dict(self.suppressed)


def finding_to_json(finding: Finding) -> dict[str, Any]:
    """Serialise a finding; kept here to avoid importing json in models."""
    return json.loads(json.dumps(finding.to_dict(), default=str))
