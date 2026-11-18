"""Tests for evidence preservation and integrity metadata."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from irkit.config import Limits, SystemPaths
from irkit.evidence import EvidenceManager


def manager(root: Path, limits: Limits | None = None) -> EvidenceManager:
    paths = SystemPaths.from_root(root)
    return EvidenceManager(paths, limits or Limits(), logging.getLogger("test"))


def test_file_evidence_hash_matches_content(tmp_path: Path) -> None:
    target = tmp_path / "passwd"
    target.write_text("root:x:0:0::/root:/bin/bash\n", encoding="utf-8")
    item = manager(tmp_path).record_file(target, "Account database", "users")
    assert item is not None
    assert item.kind == "file"
    assert item.source_path == str(target)
    assert item.sha256 == hashlib.sha256(target.read_bytes()).hexdigest()
    assert item.size == target.stat().st_size
    assert item.readable is True
    assert item.collected_at.endswith("Z")


def test_file_evidence_is_deduplicated(tmp_path: Path) -> None:
    target = tmp_path / "passwd"
    target.write_text("root:x:0:0::/root:/bin/bash\n", encoding="utf-8")
    instance = manager(tmp_path)
    first = instance.record_file(target, "Account database", "users")
    second = instance.record_file(target, "Account database", "users")
    assert first is not None and first is second
    assert len(instance.items) == 1


def test_secret_metadata_is_recorded_without_hash(tmp_path: Path) -> None:
    target = tmp_path / "shadow"
    target.write_text("root:$6$secret$hash:19000:0:99999:7:::\n", encoding="utf-8")
    item = manager(tmp_path).record_file(target, "Shadow database", "users", hash_content=False)
    assert item is not None
    assert item.sha256 is None
    assert item.size == target.stat().st_size
    assert "$6$" not in str(item.to_dict())


def test_missing_file_is_recorded_as_unreadable(tmp_path: Path) -> None:
    item = manager(tmp_path).record_file(tmp_path / "missing", "Missing", "users")
    assert item is not None
    assert item.readable is False
    assert item.sha256 is None
    assert item.notes


def test_directory_and_command_evidence(tmp_path: Path) -> None:
    directory = tmp_path / "etc"
    directory.mkdir()
    instance = manager(tmp_path)
    recorded_dir = instance.record_directory(directory, "Configuration directory", "system")
    command = instance.record_command("last -F", "alice pts/0\n", "Login history", "users")
    assert recorded_dir is not None and recorded_dir.kind == "directory"
    assert command is not None and command.kind == "command"
    assert command.sha256 == hashlib.sha256(b"alice pts/0\n").hexdigest()
    assert command.source_path is None
    assert command.command == "last -F"


def test_data_evidence_is_stable_for_equal_payloads(tmp_path: Path) -> None:
    instance = manager(tmp_path)
    first = instance.record_data("summary", {"b": 2, "a": 1}, "Summary", "system")
    second = instance.record_data("summary", {"a": 1, "b": 2}, "Summary", "system")
    assert first is not None and second is not None
    assert first.sha256 == second.sha256


def test_evidence_capacity_drops_further_items(tmp_path: Path) -> None:
    instance = manager(tmp_path, Limits(max_evidence_items=1))
    first = instance.record_data("one", {"a": 1}, "One", "system")
    second = instance.record_data("two", {"b": 2}, "Two", "system")
    assert first is not None
    assert second is None
    assert instance.dropped == 1
    assert len(instance.items) == 1


def test_symlink_evidence_records_target_note(tmp_path: Path) -> None:
    target = tmp_path / "real.conf"
    target.write_text("value\n", encoding="utf-8")
    link = tmp_path / "link.conf"
    link.symlink_to(target)
    item = manager(tmp_path).record_file(link, "Symlinked config", "filesystem")
    assert item is not None
    assert "symlink" in (item.notes or "")
    assert item.sha256 == hashlib.sha256(b"value\n").hexdigest()
