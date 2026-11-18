"""Tests for HTML/JSON report rendering."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from irkit.context import document_digest, verify_document_integrity
from irkit.report import ReportError, render_html, write_report


def test_html_report_contains_expected_sections(investigation_document: dict) -> None:
    html = render_html(investigation_document)
    assert html.startswith("<!DOCTYPE html>")
    assert "Linux Incident Response Report" in html
    assert "Executive summary" in html
    assert "Detailed findings" in html
    assert "Evidence register" in html
    assert "Integrity and methodology" in html
    assert "Document integrity" in html
    assert "Limitations and ethical use" in html
    assert "SHA-256 verified" in html
    assert investigation_document["investigation"]["id"] in html


def test_html_escapes_attacker_controlled_text(investigation_document: dict) -> None:
    document = json.loads(json.dumps(investigation_document))
    document["findings"][0]["description"] = '<script>alert("xss")</script>'
    html = render_html(document, redact=False)
    assert '<script>alert("xss")</script>' not in html
    assert "&lt;script&gt;" in html


def test_report_time_redaction_removes_secrets(investigation_document: dict) -> None:
    document = json.loads(json.dumps(investigation_document))
    document["findings"][0]["description"] = "captured password=hunter2 in command line"
    html = render_html(document)
    assert "hunter2" not in html
    assert "[REDACTED]" in html


def test_redacted_copy_is_resealed(investigation_document: dict) -> None:
    document = json.loads(json.dumps(investigation_document))
    document["findings"][0]["description"] = "token=abcdef123456"
    html = render_html(document)
    assert "abcdef123456" not in html

    # A document that is already redacted must keep its original digest.
    original_digest = investigation_document["integrity"]["sha256"]
    assert document_digest(investigation_document) == original_digest
    assert verify_document_integrity(investigation_document) is True


def test_write_report_creates_all_artefacts(
    investigation_document: dict, tmp_path: Path
) -> None:
    source = tmp_path / "latest.json"
    source.write_text(json.dumps(investigation_document), encoding="utf-8")
    result = write_report(source, tmp_path / "reports")

    for key in ("html_path", "json_path", "latest_html", "latest_json"):
        path = Path(result[key])
        assert path.is_file()
        assert path.stat().st_size > 0
    assert result["integrity_valid"] is True

    report = json.loads(Path(result["json_path"]).read_text(encoding="utf-8"))
    assert report["investigation"]["id"] == investigation_document["investigation"]["id"]
    assert verify_document_integrity(report) is True
    assert "<!DOCTYPE html>" in Path(result["latest_html"]).read_text(encoding="utf-8")


def test_write_report_uses_input_directory_by_default(
    investigation_document: dict, tmp_path: Path
) -> None:
    source = tmp_path / "latest.json"
    source.write_text(json.dumps(investigation_document), encoding="utf-8")
    result = write_report(source)
    assert Path(result["html_path"]).parent == tmp_path
    assert Path(result["json_path"]).parent == tmp_path


def test_write_report_rejects_missing_or_invalid_input(tmp_path: Path) -> None:
    with pytest.raises(Exception):
        write_report(tmp_path / "absent.json", tmp_path / "reports")

    invalid = tmp_path / "invalid.json"
    invalid.write_text("{not json", encoding="utf-8")
    with pytest.raises(Exception):
        write_report(invalid, tmp_path / "reports")


def test_write_report_marks_tampered_input(
    investigation_document: dict, tmp_path: Path
) -> None:
    document = json.loads(json.dumps(investigation_document))
    document["summary"]["findings"] += 1
    source = tmp_path / "tampered.json"
    source.write_text(json.dumps(document), encoding="utf-8")
    result = write_report(source, tmp_path / "reports")
    assert result["integrity_valid"] is False


def test_write_report_rejects_output_file(tmp_path: Path, investigation_document: dict) -> None:
    source = tmp_path / "latest.json"
    source.write_text(json.dumps(investigation_document), encoding="utf-8")
    target = tmp_path / "not-a-directory"
    target.write_text("occupied", encoding="utf-8")
    with pytest.raises(ReportError, match="not a directory"):
        write_report(source, target)
