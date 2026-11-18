"""Tests for analyst-supplied indicator loading and validation."""

from __future__ import annotations

import json
from pathlib import Path

from irkit.iocfile import detect_type, load_indicators, normalise
from irkit.models import Severity


def test_detect_type_for_common_values() -> None:
    assert detect_type("203.0.113.5") == "ip"
    assert detect_type("2001:db8::1") == "ip"
    assert detect_type("https://example.com/a") == "url"
    assert detect_type("a" * 64) == "sha256"
    assert detect_type("b" * 40) == "sha1"
    assert detect_type("c" * 32) == "md5"
    assert detect_type("/etc/passwd") == "path"
    assert detect_type("evil.example") == "domain"
    assert detect_type("plain text value") == "string"


def test_normalise_validation() -> None:
    assert normalise("ip", "2001:0db8::1") == ("2001:db8::1", None)
    assert normalise("domain", "Evil.Example.") == ("evil.example", None)
    assert normalise("sha256", "A" * 64) == ("a" * 64, None)
    assert normalise("path", "/tmp/x") == ("/tmp/x", None)
    assert normalise("ip", "not-an-ip")[0] is None
    assert normalise("path", "relative/path")[0] is None
    assert normalise("domain", "bad domain")[0] is None
    assert normalise("url", "ftp://example.com")[0] is None
    assert normalise("sha256", "short")[0] is None
    assert normalise("string", "ab")[0] is None
    assert normalise("unknown", "value")[0] is None


def test_load_json_object_with_severity_and_description(tmp_path: Path) -> None:
    path = tmp_path / "indicators.json"
    path.write_text(
        json.dumps(
            {
                "indicators": [
                    {"type": "ip", "value": "203.0.113.5", "severity": "medium", "description": "C2"},
                    {"type": "path", "value": "/tmp/payload"},
                ]
            }
        ),
        encoding="utf-8",
    )
    indicators, errors = load_indicators(path)
    assert errors == []
    assert len(indicators) == 2
    assert indicators[0].severity is Severity.MEDIUM
    assert indicators[0].description == "C2"
    assert indicators[1].severity is Severity.HIGH


def test_load_bare_json_list_and_strings(tmp_path: Path) -> None:
    path = tmp_path / "indicators.json"
    path.write_text(json.dumps(["203.0.113.5", "evil.example", "a" * 64]), encoding="utf-8")
    indicators, errors = load_indicators(path)
    assert errors == []
    assert {indicator.type for indicator in indicators} == {"ip", "domain", "sha256"}


def test_load_plain_text_with_comments_and_prefixes(tmp_path: Path) -> None:
    path = tmp_path / "indicators.txt"
    path.write_text(
        "# comment\nip: 203.0.113.5\npath /tmp/payload\nevil.example  # trailing comment\n\n",
        encoding="utf-8",
    )
    indicators, errors = load_indicators(path)
    assert errors == []
    assert len(indicators) == 3
    assert {indicator.type for indicator in indicators} == {"ip", "path", "domain"}


def test_invalid_entries_are_reported_and_skipped(tmp_path: Path) -> None:
    path = tmp_path / "indicators.json"
    path.write_text(
        json.dumps({"indicators": [{"type": "ip", "value": "nope"}, {"value": ""}, {"type": "domain", "value": "ok.example"}]}),
        encoding="utf-8",
    )
    indicators, errors = load_indicators(path)
    assert len(indicators) == 1
    assert len(errors) == 2
    assert any("invalid IP" in error for error in errors)


def test_duplicate_indicators_keep_highest_severity(tmp_path: Path) -> None:
    path = tmp_path / "indicators.json"
    path.write_text(
        json.dumps(
            {
                "indicators": [
                    {"type": "ip", "value": "203.0.113.5", "severity": "low"},
                    {"type": "ip", "value": "203.0.113.5", "severity": "critical"},
                ]
            }
        ),
        encoding="utf-8",
    )
    indicators, errors = load_indicators(path)
    assert errors == []
    assert len(indicators) == 1
    assert indicators[0].severity is Severity.CRITICAL


def test_invalid_json_and_empty_files(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    indicators, errors = load_indicators(bad)
    assert indicators == []
    assert any("invalid JSON" in error for error in errors)

    empty = tmp_path / "empty.txt"
    empty.write_text("   \n", encoding="utf-8")
    indicators, errors = load_indicators(empty)
    assert indicators == []
    assert any("empty" in error for error in errors)


def test_missing_file_returns_error(tmp_path: Path) -> None:
    indicators, errors = load_indicators(tmp_path / "missing.json")
    assert indicators == []
    assert errors and "cannot read" in errors[0]
