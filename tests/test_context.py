"""Tests for investigation assembly, integrity and persistence."""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from irkit.config import SystemPaths, ToolkitConfig
from irkit.context import (
    Investigation,
    InvestigationError,
    document_digest,
    load_document,
    verify_document_integrity,
)


def test_document_has_expected_shape(investigation_document: dict) -> None:
    document = investigation_document
    assert document["schema"].startswith("linux-ir-toolkit/investigation/")
    assert document["tool"]["name"] == "Linux-IR-Toolkit"
    assert document["investigation"]["read_only"] is True
    assert document["investigation"]["evidence_uploaded"] is False
    assert document["investigation"]["is_root"] is False
    assert document["summary"]["findings"] == len(document["findings"])
    assert document["summary"]["evidence"] == len(document["evidence"])
    assert document["collectors"][0]["name"] == "users"
    assert document["methodology"]["mode"] == "read-only"
    assert document["summary"]["risk"]["rating"] in {"Minimal", "Low", "Elevated", "High", "Severe"}


def test_document_integrity_verifies_and_detects_tampering(investigation_document: dict) -> None:
    document = investigation_document
    assert verify_document_integrity(document) is True
    document["summary"]["findings"] += 1
    assert verify_document_integrity(document) is False


def test_digest_ignores_only_the_integrity_object(investigation_document: dict) -> None:
    document = dict(investigation_document)
    before = document_digest(document)
    document["integrity"] = {"sha256": "different"}
    assert document_digest(document) == before


def test_save_writes_timestamped_and_latest_files(
    investigation_document: dict, tmp_path: Path
) -> None:
    config = ToolkitConfig(paths=SystemPaths.from_root(tmp_path / "root"))
    investigation = Investigation(config, is_root=False)
    investigation._document = investigation_document
    written = investigation.save(tmp_path / "reports")
    json_path = Path(written["json_path"])
    latest_path = Path(written["latest_path"])
    assert json_path.is_file()
    assert latest_path.is_file()
    assert json_path.read_text(encoding="utf-8") == latest_path.read_text(encoding="utf-8")
    assert stat.S_IMODE(json_path.stat().st_mode) == 0o600
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["investigation"]["id"] == investigation_document["investigation"]["id"]


def test_load_document_round_trip(investigation_document: dict, tmp_path: Path) -> None:
    path = tmp_path / "report.json"
    path.write_text(json.dumps(investigation_document), encoding="utf-8")
    loaded = load_document(path)
    assert loaded["investigation"]["id"] == investigation_document["investigation"]["id"]


def test_load_document_rejects_invalid_input(tmp_path: Path) -> None:
    invalid_json = tmp_path / "invalid.json"
    invalid_json.write_text("{not json", encoding="utf-8")
    with pytest.raises(InvestigationError, match="invalid JSON"):
        load_document(invalid_json)

    missing_key = tmp_path / "missing.json"
    missing_key.write_text(json.dumps({"investigation": {}}), encoding="utf-8")
    with pytest.raises(InvestigationError, match="missing required key"):
        load_document(missing_key)

    not_object = tmp_path / "list.json"
    not_object.write_text("[]", encoding="utf-8")
    with pytest.raises(InvestigationError, match="JSON object"):
        load_document(not_object)

    with pytest.raises(InvestigationError, match="cannot read"):
        load_document(tmp_path / "absent.json")


def test_investigation_expands_ioc_prerequisites(config: ToolkitConfig) -> None:
    investigation = Investigation(config, is_root=False)
    document = investigation.run(["ioc"])
    names = [collector["name"] for collector in document["collectors"]]
    assert names == [
        "system",
        "users",
        "processes",
        "network",
        "ssh",
        "persistence",
        "filesystem",
        "logs",
        "ioc",
    ]
    assert document["collectors"][-1]["status"] == "skipped"


def test_investigation_rejects_unknown_collector(config: ToolkitConfig) -> None:
    investigation = Investigation(config, is_root=False)
    with pytest.raises(KeyError):
        investigation.run(["does-not-exist"])
