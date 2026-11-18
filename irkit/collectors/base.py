"""Collector base class and shared collection helpers."""

from __future__ import annotations

import logging
import traceback
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar, Iterable

from irkit.config import Limits, SystemPaths, ToolkitConfig
from irkit.evidence import EvidenceManager
from irkit.findings import FindingsFactory
from irkit.models import (
    CollectorResult,
    CollectorStatus,
    Confidence,
    EvidenceItem,
    Finding,
    Severity,
)
from irkit.utils import (
    CommandResult,
    FileRead,
    iso_utc,
    read_text_file,
    run_command,
    utc_now,
)


class CollectorContext:
    """Shared services and previously collected results."""

    def __init__(
        self,
        config: ToolkitConfig,
        evidence: EvidenceManager,
        findings: FindingsFactory,
        logger: logging.Logger,
        *,
        is_root: bool | None = None,
        results: dict[str, CollectorResult] | None = None,
        started_at: datetime | None = None,
    ) -> None:
        self.config = config
        self.evidence = evidence
        self.findings = findings
        self.logger = logger
        self.is_root = is_root
        self.results: dict[str, CollectorResult] = results if results is not None else {}
        self.started_at = started_at or utc_now()

    @property
    def paths(self) -> SystemPaths:
        return self.config.paths

    @property
    def limits(self) -> Limits:
        return self.config.limits

    def prior_data(self, collector_name: str) -> dict[str, Any]:
        """Return the data of an already-run collector, or an empty dict."""
        result = self.results.get(collector_name)
        return result.data if result else {}

    def add_result(self, result: CollectorResult) -> None:
        self.results[result.name] = result


class BaseCollector(ABC):
    """Template-method base for all collectors.

    Subclasses implement :meth:`run` and populate ``self.data``,
    ``self.findings``, ``self.evidence``, ``self.errors`` and ``self.warnings``.
    The base class guarantees that unexpected exceptions become a failed
    collector result instead of aborting the whole investigation.
    """

    name: ClassVar[str] = "base"
    description: ClassVar[str] = "Base collector"
    requires_root: ClassVar[bool] = False

    def __init__(self, ctx: CollectorContext) -> None:
        self.ctx = ctx
        self.data: dict[str, Any] = {}
        self.findings: list[Finding] = []
        self.evidence: list[EvidenceItem] = []
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self._warned: set[str] = set()
        self._evidence_cap_warned = False
        self.skipped_reason: str | None = None

    # -- template method ---------------------------------------------------
    def collect(self) -> CollectorResult:
        started = utc_now()
        status = CollectorStatus.OK
        try:
            self.run()
        except Exception as exc:  # noqa: BLE001 - collectors must never crash the run
            self.errors.append(f"unhandled {type(exc).__name__}: {exc}")
            self.ctx.logger.error(
                "collector %s failed: %s\n%s",
                self.name,
                exc,
                traceback.format_exc(limit=5),
            )
            status = CollectorStatus.ERROR
        finished = utc_now()
        if self.skipped_reason:
            status = CollectorStatus.SKIPPED
            self.data.setdefault("skipped_reason", self.skipped_reason)
        elif status is CollectorStatus.OK:
            if self.errors:
                status = CollectorStatus.PARTIAL
            elif self.warnings:
                status = CollectorStatus.PARTIAL
        if self.requires_root and not self.is_root and not self.errors:
            self.note_warning("running without root: results are limited to world-readable artefacts")
            if status is CollectorStatus.OK:
                status = CollectorStatus.PARTIAL
        duration = int((finished - started).total_seconds() * 1000)
        return CollectorResult(
            name=self.name,
            description=self.description,
            status=status,
            started_at=iso_utc(started),
            finished_at=iso_utc(finished),
            duration_ms=duration,
            data=self.data,
            findings=self.findings,
            evidence=self.evidence,
            errors=self.errors,
            warnings=self.warnings,
            requires_root=self.requires_root,
        )

    @abstractmethod
    def run(self) -> None:
        """Perform collection.  Must not modify the system."""

    def mark_skipped(self, reason: str) -> None:
        """Mark the collector as intentionally skipped (not a failure)."""
        self.skipped_reason = reason

    # -- helpers -----------------------------------------------------------
    @property
    def is_root(self) -> bool:
        if self.ctx.is_root is not None:
            return self.ctx.is_root
        import os

        return os.geteuid() == 0

    def rel(self, path: Path | str) -> str:
        """Render a path relative to the collection root."""
        return self.ctx.paths.rel(Path(path))

    def note_warning(self, message: str) -> None:
        if message not in self._warned:
            self._warned.add(message)
            self.warnings.append(message)
            self.ctx.logger.debug("%s: %s", self.name, message)

    def note_error(self, message: str) -> None:
        self.errors.append(message)
        self.ctx.logger.warning("%s: %s", self.name, message)

    def add_finding(
        self,
        rule_id: str,
        description: str,
        *,
        details: dict[str, Any] | None = None,
        evidence: Iterable[EvidenceItem | str] = (),
        confidence: Confidence | None = None,
        title: str | None = None,
        severity: Severity | None = None,
    ) -> Finding | None:
        finding = self.ctx.findings.create(
            rule_id,
            collector=self.name,
            description=description,
            details=details,
            evidence=evidence,
            confidence=confidence,
            title=title,
            severity=severity,
        )
        if finding is not None:
            self.findings.append(finding)
        return finding

    def add_evidence(self, item: EvidenceItem | None) -> EvidenceItem | None:
        if item is not None:
            self.evidence.append(item)
        elif not self._evidence_cap_warned:
            self._evidence_cap_warned = True
            self.note_warning("evidence item cap reached; some evidence metadata was not preserved")
        return item

    def evidence_file(
        self,
        path: Path | str,
        description: str,
        *,
        hash_content: bool = True,
    ) -> EvidenceItem | None:
        return self.add_evidence(
            self.ctx.evidence.record_file(path, description, self.name, hash_content=hash_content)
        )

    def evidence_data(self, label: str, payload: Any, description: str) -> EvidenceItem | None:
        return self.add_evidence(self.ctx.evidence.record_data(label, payload, description, self.name))

    def read_text(
        self,
        path: Path | str,
        description: str | None = None,
        *,
        max_bytes: int | None = None,
        record: bool = True,
        required: bool = False,
        hash_content: bool = True,
    ) -> str | None:
        """Read a text artefact defensively and preserve its evidence metadata.

        ``hash_content=False`` is used for secret-bearing files such as
        ``/etc/shadow`` and private keys: their metadata is preserved but their
        content is never digested or stored.
        """
        target = Path(path)
        if not target.exists():
            if required:
                self.note_warning(f"missing: {self.rel(target)}")
            return None
        result: FileRead = read_text_file(target, max_bytes or self.ctx.limits.max_read_bytes)
        if record and description:
            self.evidence_file(target, description, hash_content=hash_content and result.text is not None)
        if result.error:
            self.note_warning(f"cannot read {self.rel(target)}: {result.error}")
            return None
        if result.truncated:
            self.note_warning(f"truncated at {self.ctx.limits.max_read_bytes} bytes: {self.rel(target)}")
        return result.text

    def command(self, argv: list[str], description: str, *, record: bool = True) -> CommandResult:
        """Run an allow-listed read-only command and preserve its output digest."""
        result = run_command(argv, timeout=self.ctx.limits.command_timeout)
        if record:
            self.add_evidence(
                self.ctx.evidence.record_command(
                    result.command,
                    result.stdout,
                    description,
                    self.name,
                    ok=result.ok,
                    notes=result.error or (result.stderr.strip()[:500] if result.stderr else None),
                )
            )
        if not result.ok:
            reason = result.error or result.stderr.strip() or f"exit {result.returncode}"
            self.note_warning(f"command failed: {result.command} ({reason[:200]})")
        return result
