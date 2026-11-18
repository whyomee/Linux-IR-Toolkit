"""Tests for local IOC correlation against previously collected evidence."""

from __future__ import annotations

import hashlib
from pathlib import Path

from irkit.collectors.base import CollectorContext
from irkit.collectors.ioc import IOCCollector
from irkit.config import SystemPaths, ToolkitConfig
from irkit.models import CollectorResult, CollectorStatus, Severity


def add_prior(ctx: CollectorContext, name: str, data: dict) -> None:
    result = CollectorResult(
        name=name,
        description=name,
        status=CollectorStatus.OK,
        started_at="2026-11-17T10:00:00Z",
        finished_at="2026-11-17T10:00:01Z",
        duration_ms=1,
        data=data,
    )
    ctx.add_result(result)


def run_ioc(ctx: CollectorContext):
    collector = IOCCollector(ctx)
    return collector, collector.collect()


def test_ioc_matches_path_ip_hash_and_domain(collector_context: CollectorContext, tmp_path: Path) -> None:
    passwd = collector_context.paths.passwd
    item = collector_context.evidence.record_file(passwd, "Account database", "users")
    assert item is not None
    add_prior(
        collector_context,
        "network",
        {
            "listeners": [
                {
                    "proto": "tcp",
                    "local_address": "0.0.0.0",
                    "local_port": 4444,
                    "process": "nc",
                    "exe": "/tmp/nc",
                }
            ],
            "established": [
                {
                    "proto": "tcp",
                    "local_address": "10.0.0.5",
                    "local_port": 5555,
                    "remote_address": "203.0.113.5",
                    "remote_port": 443,
                    "process": "payload",
                }
            ],
            "remote_endpoints": [{"address": "203.0.113.5", "count": 2}],
        },
    )
    add_prior(
        collector_context,
        "processes",
        {
            "processes": [
                {
                    "name": "payload",
                    "exe": "/tmp/payload",
                    "cmdline_str": "/tmp/payload --server evil.example",
                    "cwd": "/tmp",
                }
            ]
        },
    )
    indicators = [
        {"type": "path", "value": str(passwd), "severity": "low"},
        {"type": "ip", "value": "203.0.113.5", "severity": "high"},
        {"type": "sha256", "value": item.sha256, "severity": "critical"},
        {"type": "domain", "value": "evil.example", "severity": "medium"},
    ]
    config = ToolkitConfig(
        paths=collector_context.paths,
        ioc_indicators=tuple(indicators),
        ioc_source="unit-test",
    )
    collector_context.config = config
    collector, result = run_ioc(collector_context)

    assert result.status is CollectorStatus.OK
    assert collector.data["indicator_count"] == 4
    assert collector.data["matched_indicator_count"] == 4
    assert collector.data["match_count"] >= 4
    assert {finding.rule_id for finding in result.findings} == {"IOC_MATCH", "IOC_MATCH_HASH"}
    severities = {finding.details["indicator"]["type"]: finding.severity for finding in result.findings}
    assert severities["sha256"] is Severity.CRITICAL
    assert severities["ip"] is Severity.HIGH
    assert severities["domain"] is Severity.MEDIUM
    assert severities["path"] is Severity.LOW


def test_ioc_without_indicators_is_skipped(collector_context: CollectorContext) -> None:
    collector, result = run_ioc(collector_context)
    assert result.status is CollectorStatus.SKIPPED
    assert collector.data["match_count"] == 0
    assert "No indicators" in collector.data["note"]


def test_ioc_without_matches_warns(collector_context: CollectorContext) -> None:
    collector_context.config = ToolkitConfig(
        paths=collector_context.paths,
        ioc_indicators=({"type": "ip", "value": "192.0.2.99", "severity": "high"},),
        ioc_source="unit-test",
    )
    collector, result = run_ioc(collector_context)
    assert result.status is CollectorStatus.PARTIAL
    assert collector.data["match_count"] == 0
    assert any("none of the supplied indicators matched" in warning for warning in result.warnings)


def test_ioc_hash_matching_is_exact(collector_context: CollectorContext) -> None:
    target = collector_context.paths.passwd
    target.write_text("content\n", encoding="utf-8")
    item = collector_context.evidence.record_file(target, "Account database", "users")
    assert item is not None
    digest = hashlib.sha256(b"content\n").hexdigest()
    collector_context.config = ToolkitConfig(
        paths=collector_context.paths,
        ioc_indicators=({"type": "sha256", "value": digest, "severity": "high"},),
    )
    collector, _ = run_ioc(collector_context)
    assert collector.data["match_count"] == 1
    assert collector.data["matches"][0]["collector"] == "evidence"
    assert collector.data["matches"][0]["field"] == "sha256"


def test_ioc_indicator_severity_is_validated(collector_context: CollectorContext) -> None:
    add_prior(
        collector_context,
        "users",
        {"accounts": [{"name": "root", "home": "/root", "shell": "/bin/bash", "gecos": "root"}]},
    )
    collector_context.config = ToolkitConfig(
        paths=collector_context.paths,
        ioc_indicators=({"type": "string", "value": "root", "severity": "nonsense"},),
    )
    collector, result = run_ioc(collector_context)
    assert collector.data["indicators"][0]["severity"] is Severity.HIGH
    assert result.findings
