"""Investigation orchestration and document assembly.

An :class:`Investigation` owns the shared services used by every collector
(evidence manager, findings factory, logging context), executes collectors in a
deterministic order, and assembles the final JSON document.

The document is deliberately self-describing: it records the tool version,
schema version, collection parameters, collector outcomes, every finding, every
evidence record and an integrity digest over the redacted payload.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from irkit.collectors import COLLECTOR_ORDER, expand_names, get_collector
from irkit.collectors.base import CollectorContext
from irkit.config import (
    DEFAULT_OUTPUT_DIR,
    EVIDENCE_SCHEMA,
    SCHEMA_VERSION,
    TOOL_NAME,
    TOOL_VERSION,
    ToolkitConfig,
)
from irkit.evidence import EvidenceManager
from irkit.findings import FindingsFactory
from irkit.models import CollectorResult, CollectorStatus, Finding, RiskAssessment, Severity
from irkit.redact import redact_obj
from irkit.risk import RiskEngine
from irkit.utils import canonical_json, iso_utc, sha256_text, utc_now

LOGGER = logging.getLogger(__name__)

DOCUMENT_SCHEMA = f"linux-ir-toolkit/investigation/v{SCHEMA_VERSION}"


class InvestigationError(RuntimeError):
    """Raised when an investigation cannot be assembled or written."""


class Investigation:
    """Execute collectors and build a complete investigation document."""

    def __init__(
        self,
        config: ToolkitConfig | None = None,
        *,
        logger: logging.Logger | None = None,
        is_root: bool | None = None,
        command: Iterable[str] | None = None,
    ) -> None:
        self.config = config or ToolkitConfig()
        self.logger = logger or LOGGER
        self.is_root = os.geteuid() == 0 if is_root is None else is_root
        self.command = [str(part) for part in (command or [])]
        self.evidence = EvidenceManager(self.config.paths, self.config.limits, self.logger)
        self.findings_factory = FindingsFactory(self.config.limits)
        self.results: dict[str, CollectorResult] = {}
        self.ctx = CollectorContext(
            self.config,
            self.evidence,
            self.findings_factory,
            self.logger,
            is_root=self.is_root,
            results=self.results,
        )
        self.started_at = utc_now()
        self.finished_at: datetime | None = None
        self.investigation_id = self._make_id()
        self._document: dict[str, Any] | None = None

    # -- execution ---------------------------------------------------------
    def run(self, collectors: Iterable[str] | None = None) -> dict[str, Any]:
        """Run the requested collectors and return the assembled document."""
        names = expand_names(list(collectors) if collectors is not None else None)
        self.logger.info(
            "starting investigation %s on root=%s as %s",
            self.investigation_id,
            self.config.paths.root,
            "root" if self.is_root else f"uid {os.geteuid()}",
        )
        for name in names:
            if name not in COLLECTOR_ORDER:
                raise InvestigationError(f"unknown collector: {name}")
            collector_cls = get_collector(name)
            self.logger.info("collector %s: starting", name)
            collector = collector_cls(self.ctx)
            result = collector.collect()
            self.results[name] = result
            self.ctx.add_result(result)
            self.logger.info(
                "collector %s: %s in %d ms (%d findings, %d evidence)",
                name,
                result.status.value,
                result.duration_ms,
                len(result.findings),
                len(result.evidence),
            )
        self.finished_at = utc_now()
        self._document = self.build_document(names)
        return self._document

    # -- document ----------------------------------------------------------
    @property
    def findings(self) -> list[Finding]:
        ordered: list[Finding] = []
        for result in self.results.values():
            ordered.extend(result.findings)
        return ordered

    @property
    def risk(self) -> RiskAssessment:
        return RiskEngine().assess(self.findings)

    def build_document(self, requested: Iterable[str] | None = None) -> dict[str, Any]:
        """Assemble, redact and integrity-seal the investigation document."""
        if self.finished_at is None:
            self.finished_at = utc_now()
        findings = self.findings
        risk = RiskEngine().assess(findings)
        statuses = [result.status for result in self.results.values()]
        status_counts = {status.value: statuses.count(status) for status in CollectorStatus}
        severity_counts = {severity.value: 0 for severity in Severity}
        for finding in findings:
            severity_counts[finding.severity.value] += 1

        collector_dicts = [result.to_dict() for result in self.results.values()]
        evidence_items = [item.to_dict() for item in self.evidence.items]
        requested_names = list(requested) if requested is not None else list(self.results)
        duration_ms = int((self.finished_at - self.started_at).total_seconds() * 1000)

        errors = [
            {"collector": result.name, "message": message}
            for result in self.results.values()
            for message in result.errors
        ]
        warnings = [
            {"collector": result.name, "message": message}
            for result in self.results.values()
            for message in result.warnings
        ]

        top_findings = sorted(
            findings,
            key=lambda item: (item.severity.rank, item.confidence.value, item.finding_id),
            reverse=True,
        )
        document: dict[str, Any] = {
            "schema": DOCUMENT_SCHEMA,
            "evidence_schema": EVIDENCE_SCHEMA,
            "tool": {
                "name": TOOL_NAME,
                "version": TOOL_VERSION,
                "schema_version": SCHEMA_VERSION,
            },
            "investigation": {
                "id": self.investigation_id,
                "started_at": iso_utc(self.started_at),
                "finished_at": iso_utc(self.finished_at),
                "generated_at": iso_utc(),
                "duration_ms": duration_ms,
                "hostname": os.uname().nodename,
                "root": str(self.config.paths.root),
                "euid": os.geteuid(),
                "is_root": self.is_root,
                "command": self.command,
                "collectors_requested": requested_names,
                "read_only": True,
                "evidence_uploaded": False,
                "redaction": {
                    "applied": self.config.redact_output,
                    "note": (
                        "Credential and secret patterns are redacted before serialisation."
                        if self.config.redact_output
                        else "Redaction was explicitly disabled by the operator."
                    ),
                },
            },
            "summary": {
                "risk": risk.to_dict(),
                "findings": len(findings),
                "evidence": len(evidence_items),
                "collectors": {
                    "total": len(self.results),
                    "status_counts": status_counts,
                },
                "severity_counts": severity_counts,
                "top_findings": [
                    {
                        "finding_id": finding.finding_id,
                        "title": finding.title,
                        "severity": finding.severity.value,
                        "collector": finding.collector,
                        "description": finding.description,
                    }
                    for finding in top_findings[:10]
                ],
                "errors": errors,
                "warnings": warnings,
                "evidence_dropped": self.evidence.dropped,
                "suppressed_findings": self.findings_factory.suppressed_summary(),
            },
            "findings": [finding.to_dict() for finding in findings],
            "evidence": evidence_items,
            "collectors": collector_dicts,
            "methodology": {
                "mode": "read-only",
                "description": (
                    "All collectors read files, kernel interfaces and a small allow-list of "
                    "read-only commands. No file is modified, no process is signalled, and no "
                    "evidence is transmitted off the host."
                ),
                "finding_policy": (
                    "Findings describe observed indicators. They are not proof of compromise "
                    "and must be validated against change records and business context."
                ),
            },
        }

        if self.config.redact_output:
            document = redact_obj(document)
        document["integrity"] = {
            "algorithm": "sha256",
            "scope": "canonical JSON of this document without the integrity object",
            "sha256": document_digest(document),
        }
        return document

    # -- output ------------------------------------------------------------
    def save(self, output_dir: str | Path = DEFAULT_OUTPUT_DIR) -> dict[str, Any]:
        """Write a timestamped JSON document plus ``latest.json``.

        Returns a small dictionary describing the written paths and the
        document itself.  Only the output directory is written to.
        """
        document = self._document or self.build_document()
        directory = Path(output_dir).expanduser()
        try:
            directory.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise InvestigationError(f"cannot create output directory {directory}: {exc}") from exc
        if not directory.is_dir():
            raise InvestigationError(f"output path is not a directory: {directory}")

        stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
        short_id = self.investigation_id.rsplit("-", 1)[-1]
        json_path = directory / f"ir-report-{stamp}-{short_id}.json"
        latest_path = directory / "latest.json"
        text = _render_json(document)
        _atomic_write(json_path, text)
        _atomic_write(latest_path, text)
        self.logger.info("wrote %s and %s", json_path, latest_path)
        return {
            "json_path": str(json_path),
            "latest_path": str(latest_path),
            "investigation_id": self.investigation_id,
            "document": document,
        }

    # -- internals ---------------------------------------------------------
    def _make_id(self) -> str:
        stamp = self.started_at.strftime("%Y%m%dT%H%M%SZ")
        suffix = sha256_text(f"{stamp}:{os.getpid()}:{os.geteuid()}:{self.config.paths.root}")[:8]
        return f"IR-{stamp}-{suffix}"


def document_digest(document: dict[str, Any]) -> str:
    """Compute the integrity digest over everything except the digest itself."""
    payload = {key: value for key, value in document.items() if key != "integrity"}
    return sha256_text(canonical_json(payload))


def verify_document_integrity(document: dict[str, Any]) -> bool:
    """Return ``True`` when the document's stored digest matches its payload."""
    integrity = document.get("integrity")
    if not isinstance(integrity, dict):
        return False
    stored = integrity.get("sha256")
    return isinstance(stored, str) and stored == document_digest(document)


def load_document(path: str | Path) -> dict[str, Any]:
    """Load and minimally validate an investigation JSON document."""
    target = Path(path).expanduser()
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, PermissionError) as exc:
        raise InvestigationError(f"cannot read report input {target}: {type(exc).__name__}: {exc}") from exc
    try:
        document = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvestigationError(f"invalid JSON in {target}: {exc}") from exc
    if not isinstance(document, dict):
        raise InvestigationError(f"report input must be a JSON object: {target}")
    for key in ("investigation", "summary", "findings", "evidence", "collectors"):
        if key not in document:
            raise InvestigationError(f"report input is missing required key {key!r}: {target}")
    return document


def _render_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=False, default=str) + "\n"


def _atomic_write(path: Path, text: str) -> None:
    """Write a report file atomically without touching any source evidence."""
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=str(path.parent))
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        except Exception:
            try:
                os.unlink(temporary)
            except OSError:
                pass
            raise
    except OSError as exc:
        raise InvestigationError(f"cannot write {path}: {type(exc).__name__}: {exc}") from exc


__all__ = [
    "DOCUMENT_SCHEMA",
    "Investigation",
    "InvestigationError",
    "document_digest",
    "load_document",
    "verify_document_integrity",
]
