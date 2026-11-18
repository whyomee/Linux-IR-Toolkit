"""Tests for the command-line interface.

All collection tests use the synthetic root from ``conftest`` so no host data
is read and no host utility is executed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from irkit.cli import _fail_on_exit, main
from irkit.models import Severity


def test_help_lists_commands(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--help"])
    assert excinfo.value.code == 0
    out = capsys.readouterr().out
    assert "Read-only Linux incident response" in out
    for command in (
        "system",
        "processes",
        "network",
        "users",
        "ssh",
        "persistence",
        "filesystem",
        "logs",
        "ioc",
        "collect",
        "report",
    ):
        assert command in out


def test_users_command_json_uses_fake_root(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(["users", "--root", str(fake_root), "--json", "--no-color", "--quiet"])
    assert status == 0
    captured = capsys.readouterr()
    document = json.loads(captured.out)
    assert document["investigation"]["root"] == str(fake_root.resolve())
    assert [collector["name"] for collector in document["collectors"]] == ["users"]
    rule_ids = {finding["rule_id"] for finding in document["findings"]}
    assert "USER_UID0_NONROOT" in rule_ids
    assert "USER_EMPTY_PASSWORD" in rule_ids
    # Warnings and log records must never contaminate the JSON on stdout.
    assert captured.err == "" or "Traceback" not in captured.err


def test_single_collector_writes_only_with_output(
    fake_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "single"
    status = main(
        ["users", "--root", str(fake_root), "--output", str(output), "--no-color", "--quiet"]
    )
    assert status == 0
    assert (output / "latest.json").is_file()
    document = json.loads((output / "latest.json").read_text(encoding="utf-8"))
    assert document["summary"]["findings"] == len(document["findings"])


def test_collect_with_modules_writes_evidence_json(
    fake_root: Path, tmp_path: Path
) -> None:
    output = tmp_path / "collect"
    status = main(
        [
            "collect",
            "--modules",
            "users",
            "ssh",
            "--root",
            str(fake_root),
            "--output",
            str(output),
            "--json",
            "--no-color",
            "--quiet",
        ]
    )
    assert status == 0
    latest = output / "latest.json"
    assert latest.is_file()
    document = json.loads(latest.read_text(encoding="utf-8"))
    assert [collector["name"] for collector in document["collectors"]] == ["users", "ssh"]
    assert document["evidence"]
    assert document["integrity"]["sha256"]


def test_fail_on_threshold_returns_two(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(
        [
            "users",
            "--root",
            str(fake_root),
            "--json",
            "--no-color",
            "--quiet",
            "--fail-on",
            "critical",
        ]
    )
    assert status == 2
    capsys.readouterr()


def test_fail_on_exit_unit() -> None:
    document = {
        "findings": [
            {"severity": "medium"},
            {"severity": "low"},
        ]
    }
    assert _fail_on_exit(document, None) == 0
    assert _fail_on_exit(document, "low") == 2
    assert _fail_on_exit(document, "medium") == 2
    assert _fail_on_exit(document, "high") == 0
    assert _fail_on_exit({"findings": []}, "info") == 0
    assert Severity.from_str("critical").rank > Severity.from_str("high").rank


def test_invalid_root_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(["users", "--root", str(tmp_path / "missing"), "--no-color"])
    assert status == 1
    assert "collection root does not exist" in capsys.readouterr().out


def test_unknown_module_is_a_clean_error(
    fake_root: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(
        ["collect", "--modules", "does-not-exist", "--root", str(fake_root), "--no-color"]
    )
    assert status == 1
    assert "unknown collector" in capsys.readouterr().out


def test_report_command_generates_html_and_json(
    investigation_document: dict, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    source = tmp_path / "latest.json"
    source.write_text(json.dumps(investigation_document), encoding="utf-8")
    output = tmp_path / "reports"
    status = main(
        ["report", "--input", str(source), "--output", str(output), "--json", "--no-color", "--quiet"]
    )
    assert status == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["integrity_valid"] is True
    assert Path(payload["html_path"]).is_file()
    assert Path(payload["json_path"]).is_file()
    assert Path(payload["latest_html"]).is_file()
    assert payload["risk"]["rating"]


def test_report_missing_input_is_a_clean_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    status = main(["report", "--input", str(tmp_path / "absent.json"), "--no-color"])
    assert status == 1
    assert "cannot read report input" in capsys.readouterr().out


def test_invalid_ioc_file_is_a_clean_error(
    fake_root: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    indicator_file = tmp_path / "indicators.json"
    indicator_file.write_text(json.dumps({"indicators": [{"type": "ip", "value": "nope"}]}), encoding="utf-8")
    status = main(
        [
            "ioc",
            "--root",
            str(fake_root),
            "--ioc-file",
            str(indicator_file),
            "--no-color",
        ]
    )
    assert status == 1
    assert "no usable indicators" in capsys.readouterr().out
