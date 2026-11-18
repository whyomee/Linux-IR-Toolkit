"""HTML and JSON report generation.

Reports are rendered from an investigation document produced by
:mod:`irkit.context`.  Rendering is deterministic and self-contained: the HTML
embeds its own CSS, uses no JavaScript and makes no network requests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, StrictUndefined

from irkit.context import (
    document_digest,
    load_document,
    verify_document_integrity,
)
from irkit.redact import redact_obj
from irkit.utils import iso_utc, utc_now

_TEMPLATE_DIR = Path(__file__).parent / "templates"
_TEMPLATE_NAME = "report.html.j2"
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")
_SEVERITY_COLORS = {
    "critical": "#b3123b",
    "high": "#d9480f",
    "medium": "#b7791f",
    "low": "#2b6cb0",
    "informational": "#4a5568",
}
_RATING_COLORS = {
    "Minimal": "#2f855a",
    "Low": "#2b6cb0",
    "Elevated": "#b7791f",
    "High": "#d9480f",
    "Severe": "#b3123b",
}


class ReportError(RuntimeError):
    """Raised when a report cannot be rendered or written."""


def _environment() -> Environment:
    environment = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=True,
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def pretty_json(value: Any) -> str:
        return json.dumps(value, indent=2, ensure_ascii=False, sort_keys=False, default=str)

    environment.filters["pretty_json"] = pretty_json
    environment.filters["severity_color"] = lambda value: _SEVERITY_COLORS.get(str(value), "#4a5568")
    environment.filters["rating_color"] = lambda value: _RATING_COLORS.get(str(value), "#4a5568")
    return environment


def _prepare(document: dict[str, Any], redact: bool) -> tuple[dict[str, Any], bool]:
    """Return the report document and whether the input integrity verified."""
    input_integrity = verify_document_integrity(document)
    prepared = redact_obj(document) if redact else document
    if prepared is not document and prepared != document:
        # The input was not already redacted. Re-seal the redacted copy so the
        # report itself is internally consistent, and record that this happened.
        prepared = dict(prepared)
        prepared["integrity"] = {
            "algorithm": "sha256",
            "scope": "canonical JSON of this redacted report document",
            "sha256": document_digest(prepared),
            "note": "Recomputed after applying report-time redaction.",
        }
    return prepared, input_integrity


def render_html(document: dict[str, Any], *, redact: bool = True) -> str:
    """Render a complete, self-contained HTML report."""
    prepared, integrity_valid = _prepare(document, redact)
    summary = prepared.get("summary", {})
    risk = summary.get("risk", {})
    severity_counts = summary.get("severity_counts", {})
    findings = prepared.get("findings", [])
    ordered_findings = sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.index(str(item.get("severity", "informational")))
            if str(item.get("severity", "informational")) in _SEVERITY_ORDER
            else len(_SEVERITY_ORDER),
            str(item.get("finding_id", "")),
        ),
    )
    integrity = prepared.get("integrity", {})
    context = {
        "document": prepared,
        "tool": prepared.get("tool", {}),
        "investigation": prepared.get("investigation", {}),
        "summary": summary,
        "risk": risk,
        "severity_counts": severity_counts,
        "severity_order": _SEVERITY_ORDER,
        "findings": ordered_findings,
        "evidence": prepared.get("evidence", []),
        "collectors": prepared.get("collectors", []),
        "errors": summary.get("errors", []),
        "warnings": summary.get("warnings", []),
        "top_findings": summary.get("top_findings", []),
        "integrity": integrity,
        "integrity_valid": integrity_valid,
        "rendered_at": iso_utc(),
        "report_title": "Linux Incident Response Report",
    }
    try:
        template = _environment().get_template(_TEMPLATE_NAME)
        return template.render(**context)
    except Exception as exc:  # noqa: BLE001 - surface a clear report error
        raise ReportError(f"cannot render HTML report: {type(exc).__name__}: {exc}") from exc


def write_report(
    input_path: str | Path,
    output_dir: str | Path | None = None,
    *,
    redact: bool = True,
    stem: str | None = None,
) -> dict[str, Any]:
    """Load an investigation JSON document and write HTML + JSON reports.

    Files are written atomically into ``output_dir``.  ``latest.html`` and
    ``latest-report.json`` are refreshed for convenience; the input document is
    never overwritten.
    """
    document = load_document(input_path)
    prepared, integrity_valid = _prepare(document, redact)
    directory = Path(output_dir).expanduser() if output_dir else Path(input_path).expanduser().parent
    if directory.exists() and not directory.is_dir():
        raise ReportError(f"report output path is not a directory: {directory}")
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ReportError(f"cannot create report directory {directory}: {exc}") from exc
    if not directory.is_dir():
        raise ReportError(f"report output path is not a directory: {directory}")

    stamp = utc_now().strftime("%Y%m%dT%H%M%SZ")
    short_id = str(prepared.get("investigation", {}).get("id", "report")).rsplit("-", 1)[-1]
    base = stem or f"ir-report-{stamp}-{short_id}"
    html_path = directory / f"{base}.html"
    json_path = directory / f"{base}.json"
    latest_html = directory / "latest.html"
    latest_json = directory / "latest-report.json"

    try:
        html = render_html(prepared, redact=False)
        json_text = json.dumps(prepared, indent=2, ensure_ascii=False, sort_keys=False, default=str) + "\n"
        _write_text(html_path, html)
        _write_text(json_path, json_text)
        _write_text(latest_html, html)
        _write_text(latest_json, json_text)
    except (OSError, ReportError) as exc:
        if isinstance(exc, ReportError):
            raise
        raise ReportError(f"cannot write report: {type(exc).__name__}: {exc}") from exc

    return {
        "input_path": str(Path(input_path).expanduser()),
        "html_path": str(html_path),
        "json_path": str(json_path),
        "latest_html": str(latest_html),
        "latest_json": str(latest_json),
        "integrity_valid": integrity_valid,
        "document": prepared,
    }


def _write_text(path: Path, text: str) -> None:
    try:
        path.write_text(text, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise ReportError(f"cannot write {path}: {type(exc).__name__}: {exc}") from exc


__all__ = [
    "ReportError",
    "render_html",
    "write_report",
]
