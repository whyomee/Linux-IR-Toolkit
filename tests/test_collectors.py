"""Collector tests against a synthetic filesystem root.

The autouse fixture in ``conftest`` stubs every command invocation, so these
tests never touch the developer's host.
"""

from __future__ import annotations

from typing import Type

import pytest

from irkit.collectors.base import BaseCollector, CollectorContext
from irkit.collectors.filesystem import FilesystemCollector
from irkit.collectors.logs import LogCollector
from irkit.collectors.persistence import PersistenceCollector
from irkit.collectors.ssh import SSHCollector
from irkit.collectors.users import UserCollector
from irkit.models import CollectorStatus


def run(collector_cls: Type[BaseCollector], ctx: CollectorContext):
    collector = collector_cls(ctx)
    result = collector.collect()
    return collector, result


def rules(result) -> set[str]:
    return {finding.rule_id for finding in result.findings}


# --------------------------------------------------------------------- users
def test_user_collector_detects_account_anomalies(collector_context: CollectorContext) -> None:
    collector, result = run(UserCollector, collector_context)
    assert result.status is CollectorStatus.OK
    detected = rules(result)
    assert {
        "USER_UID0_NONROOT",
        "USER_RECENT_UID0_ACCOUNT",
        "USER_RECENT_ACCOUNT",
        "USER_EMPTY_PASSWORD",
        "USER_SUDO_NOPASSWD",
        "USER_DUPLICATE_UID",
        "USER_SYSTEM_ACCOUNT_INTERACTIVE",
        "USER_SUDO_GROUP_MEMBER",
        "USER_HOME_RECENT",
    } <= detected

    data = collector.data
    assert data["uid0_accounts"] == ["root", "ghost"]
    assert data["duplicate_uids"] == {"1001": ["dup1", "dup2"]}
    assert data["shadow"]["empty_password_accounts"] == ["alice"]
    assert data["sudoers"]["nopasswd_entries"][0]["principal"] == "alice"
    assert "svc" in data["system_accounts_with_interactive_shell"]
    recent_names = {entry["name"] for entry in data["recent_accounts"]}
    assert {"ghost", "dup2"} <= recent_names


def test_shadow_evidence_never_contains_a_digest(collector_context: CollectorContext) -> None:
    collector, _ = run(UserCollector, collector_context)
    shadow_items = [item for item in collector.evidence if item.source_path.endswith("/shadow")]
    assert shadow_items
    assert all(item.sha256 is None for item in shadow_items)
    assert all("secret" not in str(item.to_dict()) for item in collector.evidence)


def test_user_collector_handles_missing_passwd(collector_context: CollectorContext) -> None:
    collector_context.paths.passwd.unlink()
    collector, result = run(UserCollector, collector_context)
    assert result.status is CollectorStatus.PARTIAL
    assert collector.data == {}
    assert any("cannot read /etc/passwd" in warning for warning in result.warnings)


# ----------------------------------------------------------------------- ssh
def test_ssh_collector_detects_weak_config_keys_and_auth(collector_context: CollectorContext) -> None:
    collector, result = run(SSHCollector, collector_context)
    detected = rules(result)
    assert {
        "SSH_ROOT_LOGIN_ENABLED",
        "SSH_PASSWORD_AUTH_ENABLED",
        "SSH_WEAK_MAX_AUTH_TRIES",
        "SSH_AUTHORIZED_KEY_WORLD_WRITABLE",
        "SSH_AUTHORIZED_KEY_RECENT",
        "SSH_PRIVATE_KEY_EXPOSED",
        "SSH_FAILED_LOGIN_BURST",
        "SSH_SUCCESS_AFTER_FAILURES",
        "SSH_ROOT_LOGIN_SUCCESS",
    } <= detected

    data = collector.data
    assert data["config"]["effective"]["permitrootlogin"] == "yes"
    assert data["authorized_keys"]["count"] == 1
    assert data["authorized_keys"]["files"][0]["key_count"] == 1
    assert data["authentication"]["failed_by_ip"]["203.0.113.5"] == 12
    assert data["authentication"]["root_accepts"][0]["source_ip"] == "198.51.100.7"


def test_private_key_is_metadata_only(collector_context: CollectorContext) -> None:
    collector, _ = run(SSHCollector, collector_context)
    key_items = [item for item in collector.evidence if item.source_path.endswith("id_rsa")]
    assert key_items
    assert all(item.sha256 is None for item in key_items)
    assert all("SHOULD-NOT-BE-HASHED" not in str(item.to_dict()) for item in key_items)


def test_ssh_collector_without_config_is_graceful(collector_context: CollectorContext) -> None:
    collector_context.paths.sshd_config.unlink()
    _, result = run(SSHCollector, collector_context)
    assert "SSH_ROOT_LOGIN_ENABLED" not in rules(result)
    assert any("no sshd configuration" in warning for warning in result.warnings)


# --------------------------------------------------------------- persistence
def test_persistence_collector_detects_cron_systemd_and_preload(
    collector_context: CollectorContext,
) -> None:
    collector, result = run(PersistenceCollector, collector_context)
    detected = rules(result)
    assert {
        "PERS_CRON_SUSPICIOUS",
        "PERS_SYSTEMD_SUSPICIOUS_EXEC",
        "PERS_SYSTEMD_RECENT",
        "PERS_LD_PRELOAD",
        "PERS_RC_LOCAL_SUSPICIOUS",
    } <= detected

    cron = collector.data["cron"]
    assert any("curl" in entry["command"] for entry in cron["entries"])
    suspicious_units = [
        unit for unit in collector.data["systemd"]["units"] if unit["path"].endswith("evil.service")
    ]
    assert suspicious_units and suspicious_units[0]["suspicious"]


def test_bare_systemd_commands_are_not_treated_as_writable_paths(
    collector_context: CollectorContext,
) -> None:
    """Regression: bare commands must not resolve against the collector's cwd."""
    collector, _ = run(PersistenceCollector, collector_context)
    normal = [
        unit
        for unit in collector.data["systemd"]["units"]
        if unit["path"].endswith("normal.service")
    ]
    assert normal
    assert normal[0]["suspicious"] == []


# ---------------------------------------------------------------- filesystem
def test_filesystem_collector_detects_suid_tmp_and_writable_config(
    collector_context: CollectorContext,
) -> None:
    collector, result = run(FilesystemCollector, collector_context)
    detected = rules(result)
    assert {
        "FS_SUID_IN_WRITABLE_DIR",
        "FS_EXEC_IN_TMP",
        "FS_HIDDEN_EXEC_IN_TMP",
        "FS_WORLD_WRITABLE_SENSITIVE",
        "FS_RECENT_SECURITY_CONFIG_CHANGE",
    } <= detected

    assert any(
        record["path"].endswith("home/alice/tool") for record in collector.data["suid"]["files"]
    )
    assert any(
        record["path"].endswith("limits.conf")
        for record in collector.data["world_writable"]["files"]
    )


def test_masked_systemd_symlink_is_not_world_writable(collector_context: CollectorContext) -> None:
    collector, _ = run(FilesystemCollector, collector_context)
    flagged = {
        record["path"]
        for record in collector.data["world_writable"]["files"]
    }
    assert not any(path.endswith("masked.service") for path in flagged)


def test_shadow_evidence_in_filesystem_has_no_digest(collector_context: CollectorContext) -> None:
    collector, _ = run(FilesystemCollector, collector_context)
    shadow_items = [item for item in collector.evidence if item.source_path.endswith("/shadow")]
    assert shadow_items
    assert all(item.sha256 is None for item in shadow_items)


# --------------------------------------------------------------------- logs
def test_log_collector_summarises_auth_events(collector_context: CollectorContext) -> None:
    collector, result = run(LogCollector, collector_context)
    assert collector.data["auth"]["available"] is True
    summary = collector.data["auth"]["summary"]
    assert summary["counts"]["ssh_failed"] == 12
    assert summary["counts"]["ssh_accepted"] == 2
    assert summary["counts"]["sudo"] == 1
    assert summary["counts"]["account"] == 1
    assert "LOG_ACCOUNT_CREATED" in rules(result)


def test_log_collector_handles_absent_logs(collector_context: CollectorContext) -> None:
    (collector_context.paths.var_log / "auth.log").unlink()
    _, result = run(LogCollector, collector_context)
    assert any("no authentication log files" in warning for warning in result.warnings)
    assert result.status is CollectorStatus.PARTIAL
