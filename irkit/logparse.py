"""Parsers for Linux authentication and system logs.

Supports syslog RFC3164 files (``/var/log/auth.log``), journald ``short-iso``
output, and gzip-compressed rotations.  Unparseable lines are ignored rather
than guessed at; callers receive only events that matched a known pattern.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator

from irkit.utils import gzip_open_text, iso_utc, utc_now

_ISO_TS = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
)
_RFC3164_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
_BODY = re.compile(r"^(?P<host>\S+)\s+(?P<prog>[^:\s]+?)(?:\[\d+\])?:\s*(?P<msg>.*)$")

_FAILED = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive/pam|none) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)(?: port (?P<port>\d+))?", re.IGNORECASE)
_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive/pam|none) for (?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)",
    re.IGNORECASE,
)
_SUDO = re.compile(r"^(?P<user>[^:]+?)\s*:\s.*?COMMAND=(?P<cmd>.*)$")
_SUDO_AUTH_FAIL = re.compile(r"authentication failure.*?(?:user=(?P<user>\S+))?", re.IGNORECASE)
_SU = re.compile(r"\(to (?P<user>\S+)\) (?P<by>\S+) on (?P<tty>\S+)")
_SU_SESSION = re.compile(r"session opened for user (?P<user>\S+?)\(uid=\d+\) by (?P<by>\S+?)\(uid=\d+\)")
_ACCOUNT = re.compile(
    r"(?:new user:\s*name=(?P<new_user>[^,\s]+)|delete user '?(?P<del_user>[^'\s]+)'?|"
    r"password changed for (?P<pw_user>\S+)|useradd|usermod|userdel|groupadd|groupmod|groupdel)",
    re.IGNORECASE,
)
_SSH_ROOT_ACCEPTED_USER = "root"


@dataclass
class AuthEvent:
    """A single normalised authentication or account-management event."""

    timestamp: str | None
    timestamp_raw: str | None
    kind: str
    program: str | None
    user: str | None
    source_ip: str | None
    port: int | None
    method: str | None
    message: str
    raw: str
    source: str

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp,
            "timestamp_raw": self.timestamp_raw,
            "kind": self.kind,
            "program": self.program,
            "user": self.user,
            "source_ip": self.source_ip,
            "port": self.port,
            "method": self.method,
            "message": self.message,
            "source": self.source,
        }


@dataclass
class LogRead:
    path: str
    lines: list[str]
    error: str | None
    truncated: bool
    bytes_read: int


def _local_timezone():
    return datetime.now().astimezone().tzinfo or timezone.utc


def split_timestamp(line: str, now: datetime | None = None) -> tuple[str | None, str | None, str]:
    """Split a leading timestamp from a log line.

    Returns ``(normalised_iso, raw_timestamp, remainder)``.  RFC3164 timestamps
    carry no year or offset; the current year and local timezone are applied,
    which is the best available interpretation for a host's own logs.
    """
    now = now or utc_now()
    iso_match = _ISO_TS.match(line)
    if iso_match:
        raw = iso_match.group("ts")
        remainder = line[iso_match.end() :].lstrip()
        candidate = raw.replace(" ", "T")
        if candidate.endswith("Z"):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            return None, raw, remainder
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_local_timezone())
        return iso_utc(parsed), raw, remainder

    rfc_match = _RFC3164_TS.match(line)
    if rfc_match:
        raw = rfc_match.group("ts")
        remainder = line[rfc_match.end() :].lstrip()
        try:
            parsed = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S")
        except ValueError:
            return None, raw, remainder
        parsed = parsed.replace(tzinfo=_local_timezone())
        if parsed - now.astimezone(parsed.tzinfo) > timedelta(days=1):
            parsed = parsed.replace(year=parsed.year - 1)
        return iso_utc(parsed), raw, remainder

    return None, None, line


def parse_auth_line(line: str, source: str, now: datetime | None = None) -> AuthEvent | None:
    """Parse one line into an :class:`AuthEvent`, or return ``None``."""
    stripped = line.rstrip("\n")
    if not stripped.strip():
        return None
    timestamp, timestamp_raw, remainder = split_timestamp(stripped, now)
    body_match = _BODY.match(remainder)
    if not body_match:
        return None
    program = body_match.group("prog")
    message = body_match.group("msg")

    def event(kind: str, **kwargs: object) -> AuthEvent:
        return AuthEvent(
            timestamp=timestamp,
            timestamp_raw=timestamp_raw,
            kind=kind,
            program=program,
            user=kwargs.get("user"),  # type: ignore[arg-type]
            source_ip=kwargs.get("source_ip"),  # type: ignore[arg-type]
            port=kwargs.get("port"),  # type: ignore[arg-type]
            method=kwargs.get("method"),  # type: ignore[arg-type]
            message=message,
            raw=stripped,
            source=source,
        )

    if program.startswith("sshd") or program == "sshd-session":
        match = _ACCEPTED.search(message)
        if match:
            return event(
                "ssh_accepted",
                user=match.group("user"),
                source_ip=match.group("ip"),
                port=int(match.group("port")),
                method=match.group("method"),
            )
        match = _FAILED.search(message)
        if match:
            return event(
                "ssh_failed",
                user=match.group("user"),
                source_ip=match.group("ip"),
                port=int(match.group("port")),
                method=match.group("method"),
            )
        match = _INVALID.search(message)
        if match:
            return event(
                "ssh_invalid_user",
                user=match.group("user"),
                source_ip=match.group("ip"),
                port=int(match.group("port")) if match.group("port") else None,
            )
        return None

    if program.startswith("sudo"):
        if "authentication failure" in message.lower():
            match = _SUDO_AUTH_FAIL.search(message)
            return event("sudo_failed", user=match.group("user") if match else None)
        match = _SUDO.search(message)
        if match:
            return event("sudo", user=match.group("user").strip(), method=match.group("cmd").strip())
        return None

    if program.startswith("su"):
        match = _SU_SESSION.search(message) or _SU.search(message)
        if match:
            return event("su", user=match.group("user"), method=match.group("by") if "by" in match.groupdict() else None)
        return None

    if program.startswith(("useradd", "usermod", "userdel", "groupadd", "groupmod", "groupdel", "passwd", "chage")):
        match = _ACCOUNT.search(message)
        if match:
            user = match.group("new_user") or match.group("del_user") or match.group("pw_user")
            return event("account", user=user, method=program)
        return None

    return None


def iter_log_lines(path: Path, max_lines: int, max_bytes: int) -> Iterator[str]:
    """Yield lines from a plain or gzipped log, bounded by lines and bytes."""
    consumed = 0
    try:
        with gzip_open_text(path) as handle:
            for count, line in enumerate(handle):
                if count >= max_lines or consumed >= max_bytes:
                    return
                consumed += len(line.encode("utf-8", errors="replace"))
                yield line
    except (PermissionError, FileNotFoundError, OSError, EOFError):
        return


def read_log(path: Path, max_lines: int, max_bytes: int) -> LogRead:
    """Read a log defensively, returning partial content on errors."""
    lines: list[str] = []
    error: str | None = None
    truncated = False
    consumed = 0
    try:
        with gzip_open_text(path) as handle:
            for count, line in enumerate(handle):
                if count >= max_lines:
                    truncated = True
                    break
                consumed += len(line.encode("utf-8", errors="replace"))
                if consumed > max_bytes:
                    truncated = True
                    break
                lines.append(line)
    except (PermissionError, FileNotFoundError, OSError, EOFError) as exc:
        error = f"{type(exc).__name__}: {exc}"
    return LogRead(path=str(path), lines=lines, error=error, truncated=truncated, bytes_read=consumed)


def parse_auth_events(lines: Iterable[str], source: str, now: datetime | None = None) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for line in lines:
        parsed = parse_auth_line(line, source, now)
        if parsed is not None:
            events.append(parsed)
    return events


def summarise_auth_events(events: Iterable[AuthEvent]) -> dict[str, object]:
    """Aggregate authentication events into counts used by collectors."""
    failed_by_ip: dict[str, int] = {}
    failed_by_user: dict[str, int] = {}
    accepted_by_ip: dict[str, int] = {}
    accepted_users: dict[str, int] = {}
    sudo_commands: list[dict[str, object]] = []
    account_events: list[dict[str, object]] = []
    invalid_users: dict[str, int] = {}
    counts = {"ssh_failed": 0, "ssh_accepted": 0, "ssh_invalid_user": 0, "sudo": 0, "sudo_failed": 0, "su": 0, "account": 0}

    for event in events:
        counts[event.kind] = counts.get(event.kind, 0) + 1
        if event.kind == "ssh_failed":
            if event.source_ip:
                failed_by_ip[event.source_ip] = failed_by_ip.get(event.source_ip, 0) + 1
            if event.user:
                failed_by_user[event.user] = failed_by_user.get(event.user, 0) + 1
        elif event.kind == "ssh_accepted":
            if event.source_ip:
                accepted_by_ip[event.source_ip] = accepted_by_ip.get(event.source_ip, 0) + 1
            if event.user:
                accepted_users[event.user] = accepted_users.get(event.user, 0) + 1
        elif event.kind == "ssh_invalid_user" and event.user:
            invalid_users[event.user] = invalid_users.get(event.user, 0) + 1
        elif event.kind == "sudo":
            sudo_commands.append(
                {"timestamp": event.timestamp, "user": event.user, "command": event.method, "source": event.source}
            )
        elif event.kind == "account":
            account_events.append(
                {
                    "timestamp": event.timestamp,
                    "user": event.user,
                    "action": event.method,
                    "message": event.message,
                    "source": event.source,
                }
            )

    def top(mapping: dict[str, int], limit: int = 10) -> list[dict[str, object]]:
        return [
            {"value": key, "count": value}
            for key, value in sorted(mapping.items(), key=lambda item: item[1], reverse=True)[:limit]
        ]

    return {
        "counts": counts,
        "failed_by_ip": top(failed_by_ip),
        "failed_by_user": top(failed_by_user),
        "accepted_by_ip": top(accepted_by_ip),
        "accepted_users": top(accepted_users),
        "invalid_users": top(invalid_users),
        "sudo_commands": sudo_commands[-200:],
        "account_events": account_events[-100:],
        "total_events": sum(counts.values()),
    }
