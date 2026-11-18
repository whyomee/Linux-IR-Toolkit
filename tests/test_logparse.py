"""Tests for authentication/syslog parsing and bounded log reads."""

from __future__ import annotations

import gzip
from datetime import datetime, timezone
from pathlib import Path

from irkit.logparse import (
    parse_auth_events,
    parse_auth_line,
    read_log,
    split_timestamp,
    summarise_auth_events,
)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)


def test_iso_timestamp_is_normalised_to_utc() -> None:
    iso, raw, remainder = split_timestamp("2026-11-17T10:00:00Z host prog: message")
    assert iso == "2026-11-17T10:00:00Z"
    assert raw == "2026-11-17T10:00:00Z"
    assert remainder == "host prog: message"


def test_rfc3164_timestamp_uses_supplied_year() -> None:
    iso, raw, remainder = split_timestamp("Nov 17 10:00:00 host prog: message", now=NOW)
    # RFC3164 has no offset, so the parser interprets the wall clock in the
    # host's local timezone and then normalises it to UTC.
    expected = (
        datetime(2026, 11, 17, 10, 0, 0)
        .astimezone()
        .astimezone(timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    assert iso == expected
    assert raw == "Nov 17 10:00:00"
    assert remainder == "host prog: message"


def test_line_without_timestamp_returns_none() -> None:
    iso, raw, remainder = split_timestamp("plain message without timestamp")
    assert iso is None
    assert raw is None
    assert remainder == "plain message without timestamp"


def test_parse_accepted_ssh_login() -> None:
    event = parse_auth_line(
        "2026-11-17T10:00:00Z host sshd[123]: Accepted publickey for alice from 192.0.2.10 port 2222 ssh2",
        "auth.log",
    )
    assert event is not None
    assert event.kind == "ssh_accepted"
    assert event.user == "alice"
    assert event.source_ip == "192.0.2.10"
    assert event.port == 2222
    assert event.method == "publickey"


def test_parse_failed_login_for_invalid_user() -> None:
    event = parse_auth_line(
        "2026-11-17T10:00:00Z host sshd[123]: Failed password for invalid user bob "
        "from 203.0.113.5 port 4444 ssh2",
        "auth.log",
    )
    assert event is not None
    assert event.kind == "ssh_failed"
    assert event.user == "bob"
    assert event.source_ip == "203.0.113.5"


def test_parse_invalid_user_and_unrelated_sshd_message() -> None:
    invalid = parse_auth_line(
        "2026-11-17T10:00:00Z host sshd[123]: Invalid user mallory from 198.51.100.2",
        "auth.log",
    )
    assert invalid is not None
    assert invalid.kind == "ssh_invalid_user"
    assert invalid.port is None
    assert parse_auth_line("2026-11-17T10:00:00Z host sshd[123]: Server listening on 0.0.0.0", "auth.log") is None


def test_parse_sudo_su_and_account_events() -> None:
    sudo = parse_auth_line(
        "2026-11-17T10:00:00Z host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/id",
        "auth.log",
    )
    assert sudo is not None and sudo.kind == "sudo" and sudo.user == "alice"
    assert sudo.method == "/usr/bin/id"

    su = parse_auth_line(
        "2026-11-17T10:00:00Z host su: (to root) alice on pts/0",
        "auth.log",
    )
    assert su is not None and su.kind == "su" and su.user == "root"

    account = parse_auth_line(
        "2026-11-17T10:00:00Z host useradd[42]: new user: name=backdoor, UID=1002, "
        "GID=1002, home=/home/backdoor, shell=/bin/bash",
        "auth.log",
    )
    assert account is not None
    assert account.kind == "account"
    assert account.user == "backdoor"


def test_summarise_counts_and_ranking() -> None:
    lines = [
        "2026-11-17T10:00:00Z host sshd[1]: Failed password for bob from 203.0.113.5 port 1 ssh2",
        "2026-11-17T10:01:00Z host sshd[1]: Failed password for bob from 203.0.113.5 port 2 ssh2",
        "2026-11-17T10:02:00Z host sshd[1]: Failed password for carol from 198.51.100.9 port 3 ssh2",
        "2026-11-17T10:03:00Z host sshd[1]: Accepted password for alice from 192.0.2.1 port 4 ssh2",
    ]
    summary = summarise_auth_events(parse_auth_events(lines, "auth.log"))
    assert summary["counts"]["ssh_failed"] == 3
    assert summary["counts"]["ssh_accepted"] == 1
    assert summary["failed_by_ip"][0] == {"value": "203.0.113.5", "count": 2}
    assert summary["accepted_users"] == [{"value": "alice", "count": 1}]
    assert summary["total_events"] == 4


def test_parse_auth_events_skips_unparseable_lines() -> None:
    events = parse_auth_events(
        ["garbage", "", "2026-11-17T10:00:00Z host sshd[1]: Accepted password for a from 1.2.3.4 port 5 ssh2"],
        "auth.log",
    )
    assert len(events) == 1


def test_read_log_handles_missing_file(tmp_path: Path) -> None:
    result = read_log(tmp_path / "missing.log", max_lines=10, max_bytes=1024)
    assert result.lines == []
    assert result.error is not None
    assert result.truncated is False


def test_read_log_truncates_by_line_count(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_text("one\ntwo\nthree\n", encoding="utf-8")
    result = read_log(path, max_lines=2, max_bytes=1024)
    assert result.lines == ["one\n", "two\n"]
    assert result.truncated is True


def test_read_log_supports_gzip_rotation(tmp_path: Path) -> None:
    path = tmp_path / "auth.log.1.gz"
    with gzip.open(path, "wt", encoding="utf-8") as handle:
        handle.write("2026-11-17T10:00:00Z host sshd[1]: Accepted password for a from 1.2.3.4 port 5 ssh2\n")
    result = read_log(path, max_lines=10, max_bytes=4096)
    assert result.error is None
    assert len(result.lines) == 1
