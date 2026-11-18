"""Low-level helpers: safe reads, hashing, command execution and /proc parsing.

All helpers are defensive: restricted permissions, disappearing processes,
binary files and truncated output are expected conditions and are reported to
the caller rather than raised.
"""

from __future__ import annotations

import grp
import hashlib
import json
import os
import pwd
import socket
import stat
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

#: Read-only utilities the toolkit is permitted to execute.
ALLOWED_COMMANDS = frozenset(
    {
        "last",
        "lastlog",
        "who",
        "journalctl",
        "systemctl",
        "sshd",
        "sshd_config",
        "systemd-detect-virt",
        "getenforce",
        "aa-status",
        "uname",
        "lsattr",
    }
)


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def iso_utc(value: datetime | float | int | None = None) -> str:
    """Format a datetime or epoch timestamp as ISO-8601 UTC with ``Z``."""
    if value is None:
        moment = utc_now()
    elif isinstance(value, (int, float)):
        moment = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        moment = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_iso(value: str) -> datetime | None:
    """Parse an ISO-8601 timestamp, returning ``None`` when malformed."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def human_duration(seconds: float | int | None) -> str:
    """Render a duration in seconds as a compact human string."""
    if seconds is None:
        return "unknown"
    total = max(0, int(seconds))
    days, rem = divmod(total, 86_400)
    hours, rem = divmod(rem, 3_600)
    minutes, secs = divmod(rem, 60)
    parts: list[str] = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes and not days:
        parts.append(f"{minutes}m")
    if not parts:
        parts.append(f"{secs}s")
    return " ".join(parts)


def human_bytes(size: int | float | None) -> str:
    """Render a byte count as a compact human string."""
    if size is None:
        return "unknown"
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024.0 or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{value:.1f} TiB"


def truncate(text: str, limit: int) -> str:
    """Truncate ``text`` to ``limit`` characters with an explicit marker."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit)] + f"... [truncated {len(text) - limit} chars]"


def canonical_json(value: Any) -> str:
    """Stable JSON encoding used for integrity hashes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


@dataclass
class FileRead:
    """Result of a bounded, defensive file read."""

    text: str | None
    error: str | None
    truncated: bool = False
    size: int | None = None


def read_text_file(
    path: Path | str,
    max_bytes: int = 4 * 1024 * 1024,
    *,
    errors: str = "replace",
) -> FileRead:
    """Read a text file without ever raising for expected failures.

    Non-regular files (FIFOs, devices, sockets) are refused.  Symlinks are
    followed because configuration files are commonly symlinked, but the
    resolved path is available to callers via :func:`file_metadata`.
    """
    target = Path(path)
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (PermissionError, FileNotFoundError, NotADirectoryError, OSError) as exc:
        return FileRead(None, f"{type(exc).__name__}: {exc}")
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return FileRead(None, f"not a regular file (mode {oct(info.st_mode)})", size=info.st_size)
        with os.fdopen(fd, "rb", closefd=False) as handle:
            raw = handle.read(max_bytes + 1)
    except OSError as exc:
        return FileRead(None, f"{type(exc).__name__}: {exc}")
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    truncated = len(raw) > max_bytes
    if truncated:
        raw = raw[:max_bytes]
    return FileRead(
        raw.decode("utf-8", errors=errors),
        None,
        truncated=truncated,
        size=info.st_size,
    )


def sha256_file(path: Path | str, max_bytes: int | None = 256 * 1024 * 1024) -> tuple[str | None, int, str | None]:
    """Hash a file's content without modifying it.

    Returns ``(digest, bytes_read, error)``.  Files larger than ``max_bytes``
    are deliberately *not* partially hashed: the digest is ``None`` and the
    reason is returned, because a partial hash is not a valid integrity value.
    """
    target = str(path)
    try:
        fd = os.open(target, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    except (PermissionError, FileNotFoundError, OSError) as exc:
        return None, 0, f"{type(exc).__name__}: {exc}"
    digest = hashlib.sha256()
    total = 0
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            return None, 0, f"not a regular file (mode {oct(info.st_mode)})"
        if max_bytes is not None and info.st_size > max_bytes:
            return None, 0, f"not hashed: size {info.st_size} exceeds limit {max_bytes}"
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
    except OSError as exc:
        return None, total, f"{type(exc).__name__}: {exc}"
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    return digest.hexdigest(), total, None


def mode_to_rwx(mode: int) -> str:
    """Convert a stat mode to a symbolic permission string."""
    return stat.filemode(mode)


def is_world_writable(mode: int) -> bool:
    return bool(mode & stat.S_IWOTH)


def is_suid(mode: int) -> bool:
    return bool(mode & stat.S_ISUID)


def is_sgid(mode: int) -> bool:
    return bool(mode & stat.S_ISGID)


def owner_name(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def file_metadata(path: Path | str) -> dict[str, Any]:
    """Return non-secret metadata for a path using ``lstat`` semantics.

    ``lstat`` is used so a symlink is reported as a link rather than silently
    describing its target.  Callers that need the target should say so.
    """
    target = Path(path)
    try:
        info = target.lstat()
    except (PermissionError, FileNotFoundError, OSError) as exc:
        return {"path": str(target), "error": f"{type(exc).__name__}: {exc}"}
    return {
        "path": str(target),
        "size": info.st_size,
        "mode": mode_to_rwx(info.st_mode),
        "mode_octal": oct(stat.S_IMODE(info.st_mode)),
        "owner": owner_name(info.st_uid),
        "uid": info.st_uid,
        "group": group_name(info.st_gid),
        "gid": info.st_gid,
        "mtime": iso_utc(info.st_mtime),
        "ctime": iso_utc(info.st_ctime),
        "atime": iso_utc(info.st_atime),
        "is_symlink": stat.S_ISLNK(info.st_mode),
        "is_regular": stat.S_ISREG(info.st_mode),
        "is_directory": stat.S_ISDIR(info.st_mode),
        "is_world_writable": is_world_writable(info.st_mode),
        "is_suid": is_suid(info.st_mode),
        "is_sgid": is_sgid(info.st_mode),
    }


@dataclass
class CommandResult:
    """Outcome of a read-only command invocation."""

    argv: list[str]
    ok: bool
    returncode: int | None
    stdout: str
    stderr: str
    error: str | None = None
    duration_ms: int = 0
    truncated: bool = False

    @property
    def command(self) -> str:
        return " ".join(self.argv)


def run_command(
    argv: Sequence[str],
    timeout: int = 20,
    *,
    max_output_bytes: int = 2 * 1024 * 1024,
    allowed: frozenset[str] = ALLOWED_COMMANDS,
) -> CommandResult:
    """Run a read-only utility with a timeout and bounded output.

    The command name must be in the allow-list, and ``shell=True`` is never
    used.  A sanitised locale keeps parsing deterministic across hosts.
    """
    args = [str(part) for part in argv]
    if not args:
        return CommandResult(args, False, None, "", "", "empty command")
    executable = Path(args[0]).name
    if executable not in allowed:
        return CommandResult(args, False, None, "", "", f"command not allowed: {executable}")

    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "HOME": os.environ.get("HOME", "/root"),
        "SYSTEMD_PAGER": "cat",
        "PAGER": "cat",
    }
    started = time.monotonic()
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=env,
            stdin=subprocess.DEVNULL,
        )
        duration = int((time.monotonic() - started) * 1000)
        stdout = completed.stdout[:max_output_bytes].decode("utf-8", errors="replace")
        stderr = completed.stderr[:max_output_bytes].decode("utf-8", errors="replace")
        truncated = len(completed.stdout) > max_output_bytes or len(completed.stderr) > max_output_bytes
        return CommandResult(
            argv=args,
            ok=completed.returncode == 0,
            returncode=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            duration_ms=duration,
            truncated=truncated,
        )
    except FileNotFoundError:
        return CommandResult(args, False, None, "", "", "command not found")
    except subprocess.TimeoutExpired:
        return CommandResult(args, False, None, "", "", f"timed out after {timeout}s")
    except OSError as exc:
        return CommandResult(args, False, None, "", "", f"{type(exc).__name__}: {exc}")


def decode_proc_address(hex_address: str, family: int) -> str:
    """Decode an address from ``/proc/net/{tcp,tcp6,udp,udp6}``.

    The kernel prints IPv4 addresses in host (little-endian) byte order and
    IPv6 addresses as four little-endian 32-bit words.
    """
    raw = bytes.fromhex(hex_address)
    if family == socket.AF_INET:
        if len(raw) != 4:
            raise ValueError(f"invalid IPv4 address: {hex_address!r}")
        return socket.inet_ntoa(raw[::-1])
    if family == socket.AF_INET6:
        if len(raw) != 16:
            raise ValueError(f"invalid IPv6 address: {hex_address!r}")
        reordered = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
        return socket.inet_ntop(socket.AF_INET6, reordered)
    raise ValueError(f"unsupported address family: {family}")


def split_proc_address(value: str, family: int) -> tuple[str, int]:
    """Split ``ADDR:PORT`` from procfs into ``(address, port)``."""
    if ":" not in value:
        raise ValueError(f"invalid proc address: {value!r}")
    address_hex, port_hex = value.rsplit(":", 1)
    return decode_proc_address(address_hex, family), int(port_hex, 16)


def iter_files(
    root: Path,
    *,
    max_depth: int = 3,
    max_entries: int = 10_000,
    budget_seconds: float = 30.0,
    skip_names: frozenset[str] = frozenset(),
) -> Iterator[Path]:
    """Walk ``root`` defensively, yielding regular files.

    Symlinks are never followed (avoids loops and escaping the scan root),
    permission errors are skipped, and both an entry cap and a wall-clock
    budget bound the traversal.
    """
    if not root.is_dir():
        return
    deadline = time.monotonic() + budget_seconds
    seen = 0
    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        directory, depth = stack.pop()
        if time.monotonic() > deadline or seen >= max_entries:
            return
        try:
            entries = list(os.scandir(directory))
        except (PermissionError, FileNotFoundError, OSError):
            continue
        for entry in entries:
            seen += 1
            if seen > max_entries or time.monotonic() > deadline:
                return
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if depth < max_depth and entry.name not in skip_names:
                        stack.append((Path(entry.path), depth + 1))
                    continue
                if entry.is_file(follow_symlinks=False):
                    yield Path(entry.path)
            except (PermissionError, FileNotFoundError, OSError):
                continue


def gzip_open_text(path: Path):
    """Open a plain or gzip-compressed log file in text mode."""
    if path.suffix == ".gz":
        import gzip

        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "rt", encoding="utf-8", errors="replace")


def safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))
