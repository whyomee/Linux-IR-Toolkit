"""Log analysis collector.

Parses authentication logs (plain, rotated and gzip), syslog-style logs and the
systemd journal.  Missing files and permission errors degrade gracefully and
are recorded as warnings, not findings.
"""

from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from irkit.collectors.base import BaseCollector
from irkit.logparse import (
    AuthEvent,
    parse_auth_events,
    read_log,
    split_timestamp,
    summarise_auth_events,
)
from irkit.models import Confidence
from irkit.patterns import match_patterns
from irkit.utils import iso_utc, truncate

_ERROR_WORDS = re.compile(
    r"(?i)\b(error|failed|failure|segfault|oom[- ]?kill|denied|panic|critical|alert|emerg|apparmor=\"DENIED)\b"
)
_PROGRAM = re.compile(r"^(?P<host>\S+)\s+(?P<prog>[^:\s]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$")

_AUTH_PATTERNS = ["auth.log", "auth.log.*", "secure", "secure.*"]
_SYSLOG_PATTERNS = [
    "syslog",
    "syslog.*",
    "messages",
    "messages.*",
    "kern.log",
    "kern.log.*",
    "daemon.log",
    "daemon.log.*",
]


class LogCollector(BaseCollector):
    name = "logs"
    description = "Authentication, syslog and journal analysis"
    requires_root = False

    def run(self) -> None:
        auth = self._auth_logs()
        syslog = self._syslog_logs()
        journal = self._journal(need_auth=not auth["available"])
        # Journal events are only folded into the authentication timeline when no
        # auth log files were available.  Mixing both would double-count events
        # on hosts that log to a file and to journald simultaneously.
        if not auth["available"] and journal.get("events"):
            auth["events"].extend(journal["events"])
            auth["summary"] = summarise_auth_events(
                [
                    AuthEvent(
                        timestamp=item.get("timestamp"),
                        timestamp_raw=item.get("timestamp_raw"),
                        kind=str(item.get("kind")),
                        program=item.get("program"),
                        user=item.get("user"),
                        source_ip=item.get("source_ip"),
                        port=item.get("port"),
                        method=item.get("method"),
                        message=str(item.get("message", "")),
                        raw=str(item.get("raw", "")),
                        source=str(item.get("source", "journalctl")),
                    )
                    for item in journal["events"]
                ]
            )
            auth["available"] = True
            auth["sources"].append({"path": "journalctl", "events_parsed": len(journal["events"])})

        self.data.update({"auth": auth, "syslog": syslog, "journal": journal})
        self._auth_findings(auth)
        self._empty_log_findings(auth.get("sources", []))

    # -- auth --------------------------------------------------------------
    def _auth_logs(self) -> dict[str, Any]:
        files = self.ctx.paths.log_candidates(_AUTH_PATTERNS)
        files = sorted(files, key=self._mtime, reverse=True)[: self.ctx.limits.max_log_files]
        sources: list[dict[str, Any]] = []
        events: list[AuthEvent] = []
        for path in files:
            per_file = max(1000, self.ctx.limits.max_log_lines // max(1, len(files)))
            log = read_log(path, per_file, self.ctx.limits.max_read_bytes * 4)
            self.evidence_file(path, f"Authentication log ({path.name})")
            parsed = parse_auth_events(log.lines, self.rel(path))
            events.extend(parsed)
            sources.append(
                {
                    "path": self.rel(path),
                    "lines_read": len(log.lines),
                    "events_parsed": len(parsed),
                    "truncated": log.truncated,
                    "error": log.error,
                    "size": self._size(path),
                    "mtime": iso_utc(self._mtime(path)) if self._mtime(path) else None,
                }
            )
            if log.error:
                self.note_warning(f"cannot read {self.rel(path)}: {log.error}")
        if not files:
            self.note_warning("no authentication log files were found in /var/log")
        summary = summarise_auth_events(events)
        event_dicts = [
            {
                "timestamp": event.timestamp,
                "kind": event.kind,
                "program": event.program,
                "user": event.user,
                "source_ip": event.source_ip,
                "port": event.port,
                "method": event.method,
                "message": truncate(event.message, 500),
                "source": event.source,
            }
            for event in events[:2000]
        ]
        return {
            "available": bool(files),
            "sources": sources,
            "summary": summary,
            "events": event_dicts,
            "event_count": len(events),
        }

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    @staticmethod
    def _size(path: Path) -> int | None:
        try:
            return path.stat().st_size
        except OSError:
            return None

    def _auth_findings(self, auth: dict[str, Any]) -> None:
        if not auth.get("available"):
            return
        summary = auth.get("summary", {})
        counts = summary.get("counts", {})
        evidence = [item for item in self.evidence if item.source_path and ("auth.log" in item.source_path or "secure" in item.source_path)]
        thresholds = self.ctx.config.thresholds

        total_failures = int(counts.get("ssh_failed", 0)) + int(counts.get("sudo_failed", 0))
        if total_failures >= thresholds.ssh_failures_total:
            top_ips = summary.get("failed_by_ip", [])[:5]
            self.add_finding(
                "LOG_AUTH_FAILURE_BURST",
                f"{total_failures} authentication failures were recorded (top sources: "
                + ", ".join(f"{item['value']} ({item['count']})" for item in top_ips)
                + ").",
                details={
                    "total_failures": total_failures,
                    "counts": counts,
                    "top_sources": top_ips,
                    "top_users": summary.get("failed_by_user", [])[:5],
                },
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        for command in summary.get("sudo_commands", []):
            text = str(command.get("command") or "")
            patterns = match_patterns(text)
            if not patterns:
                continue
            self.add_finding(
                "LOG_SUDO_SUSPICIOUS_COMMAND",
                f"Sudo command by {command.get('user')} matches "
                + ", ".join(item["name"] for item in patterns)
                + f": {truncate(text, 300)}",
                details={**command, "patterns": patterns},
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        account_events = summary.get("account_events", [])
        if account_events:
            users = sorted({str(item.get("user")) for item in account_events if item.get("user")})
            self.add_finding(
                "LOG_ACCOUNT_CREATED",
                f"{len(account_events)} account or group management event(s) were recorded "
                f"(accounts: {', '.join(users) or 'unknown'}).",
                details={"count": len(account_events), "events": account_events[:50], "accounts": users},
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        su_to_root = [
            event
            for event in auth.get("events", [])
            if event.get("kind") == "su" and str(event.get("user")) == "root"
        ]
        if su_to_root:
            self.add_finding(
                "LOG_ROOT_LOGIN",
                f"{len(su_to_root)} su session(s) to root were recorded.",
                details={"count": len(su_to_root), "events": su_to_root[:20]},
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

    def _empty_log_findings(self, sources: list[dict[str, Any]]) -> None:
        for source in sources:
            if source.get("size") != 0:
                continue
            path = source.get("path", "unknown")
            self.add_finding(
                "LOG_AUTH_LOG_EMPTY",
                f"Authentication log {path} exists but is empty (0 bytes).",
                details={"path": path, "mtime": source.get("mtime")},
                evidence=[item for item in self.evidence if item.source_path and item.source_path.endswith(Path(path).name)],
                confidence=Confidence.LOW,
            )

    # -- syslog ------------------------------------------------------------
    def _syslog_logs(self) -> dict[str, Any]:
        files = self.ctx.paths.log_candidates(_SYSLOG_PATTERNS)
        files = sorted(files, key=self._mtime, reverse=True)[: self.ctx.limits.max_log_files]
        sources: list[dict[str, Any]] = []
        by_program: dict[str, int] = {}
        recent_errors: list[dict[str, Any]] = []
        error_count = 0
        for path in files:
            per_file = max(1000, self.ctx.limits.max_log_lines // max(1, len(files)))
            log = read_log(path, per_file, self.ctx.limits.max_read_bytes * 4)
            self.evidence_file(path, f"System log ({path.name})")
            sources.append(
                {
                    "path": self.rel(path),
                    "lines_read": len(log.lines),
                    "truncated": log.truncated,
                    "error": log.error,
                }
            )
            if log.error:
                self.note_warning(f"cannot read {self.rel(path)}: {log.error}")
            for line in log.lines:
                if not _ERROR_WORDS.search(line):
                    continue
                error_count += 1
                timestamp, _, remainder = split_timestamp(line)
                match = _PROGRAM.match(remainder)
                program = match.group("prog") if match else "unknown"
                by_program[program] = by_program.get(program, 0) + 1
                if len(recent_errors) < 50:
                    recent_errors.append(
                        {
                            "timestamp": timestamp,
                            "program": program,
                            "message": truncate(line.rstrip("\n"), 400),
                            "source": self.rel(path),
                        }
                    )
        return {
            "available": bool(files),
            "sources": sources,
            "error_count": error_count,
            "by_program": dict(sorted(by_program.items(), key=lambda item: item[1], reverse=True)[:25]),
            "recent_errors": recent_errors,
        }

    # -- journal -----------------------------------------------------------
    def _journal(self, need_auth: bool) -> dict[str, Any]:
        command = ["journalctl", "--no-pager", "-o", "short-iso", "-n", "5000"]
        result = self.command(command, "Journal excerpt (last 5000 entries)")
        if not result.ok:
            if need_auth:
                self.note_warning("journalctl is unavailable; journal-based authentication analysis was skipped")
            return {"used": True, "ok": False, "error": result.error or result.stderr.strip()[:300], "events": [], "error_lines": 0}
        lines = result.stdout.splitlines()
        parsed = parse_auth_events(lines, "journalctl")
        error_lines = sum(1 for line in lines if _ERROR_WORDS.search(line))
        return {
            "used": True,
            "ok": True,
            "lines": len(lines),
            "events_parsed": len(parsed),
            "events": [event.to_dict() for event in parsed[:2000]],
            "error_lines": error_lines,
        }
