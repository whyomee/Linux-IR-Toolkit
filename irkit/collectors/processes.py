"""Process investigation collector.

Enumerates processes with psutil, records executable/cmdline/start-time context
and flags execution from writable paths, deleted executables, disguised names
and known attack command lines.  It never signals or suspends a process.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import psutil

from irkit.collectors.base import BaseCollector
from irkit.models import Confidence
from irkit.patterns import match_patterns
from irkit.utils import human_bytes, iso_utc, truncate

_ATTRS = [
    "pid",
    "ppid",
    "name",
    "username",
    "exe",
    "cmdline",
    "create_time",
    "status",
    "uids",
    "terminal",
    "memory_percent",
    "num_threads",
    "cwd",
]


class ProcessCollector(BaseCollector):
    name = "processes"
    description = "Running processes, execution paths, command lines and privilege"
    requires_root = False

    def run(self) -> None:
        processes: list[dict[str, Any]] = []
        inaccessible = 0
        zombies = 0
        kernel_threads = 0
        flagged: set[int] = set()

        try:
            iterator = psutil.process_iter(attrs=_ATTRS, ad_value=None)
            for process in iterator:
                try:
                    info = process.info
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    inaccessible += 1
                    continue
                if info.get("pid") is None:
                    continue

                pid = int(info["pid"])
                name = info.get("name") or ""
                cmdline = info.get("cmdline") or []
                cmdline_str = " ".join(str(part) for part in cmdline) if cmdline else ""
                exe = info.get("exe")
                status = info.get("status") or ""
                uids = info.get("uids")
                uid = getattr(uids, "real", None) if uids is not None else None
                username = info.get("username")
                deleted = bool(exe and exe.endswith(" (deleted)"))
                if not deleted:
                    deleted = self._readlink_deleted(pid)
                display_exe = exe[:-10] if exe and exe.endswith(" (deleted)") else exe

                if status == psutil.STATUS_ZOMBIE:
                    zombies += 1
                if not exe and not cmdline:
                    kernel_threads += 1
                if (not username or not exe) and cmdline:
                    inaccessible += 1

                record = {
                    "pid": pid,
                    "ppid": info.get("ppid"),
                    "name": truncate(name, 256),
                    "username": username,
                    "uid": uid,
                    "exe": display_exe,
                    "cmdline": [truncate(str(part), 1024) for part in cmdline],
                    "cmdline_str": truncate(cmdline_str, 4096),
                    "create_time": iso_utc(info["create_time"]) if info.get("create_time") else None,
                    "status": status,
                    "terminal": info.get("terminal"),
                    "cwd": info.get("cwd"),
                    "threads": info.get("num_threads"),
                    "memory_percent": round(float(info.get("memory_percent") or 0.0), 2),
                    "deleted_executable": deleted,
                }
                processes.append(record)
                if len(processes) >= self.ctx.limits.max_processes:
                    self.note_warning(
                        f"process list truncated at {self.ctx.limits.max_processes} entries"
                    )
                    break

                if self._inspect_process(record):
                    flagged.add(pid)
        except (psutil.Error, OSError) as exc:
            self.note_error(f"process enumeration failed: {type(exc).__name__}: {exc}")

        processes.sort(key=lambda item: item["pid"])
        by_user: dict[str, int] = {}
        for record in processes:
            key = record.get("username") or "unknown"
            by_user[key] = by_user.get(key, 0) + 1

        self.data.update(
            {
                "total": len(processes),
                "kernel_threads": kernel_threads,
                "zombies": zombies,
                "inaccessible": inaccessible,
                "flagged_pids": sorted(flagged),
                "by_user": dict(sorted(by_user.items(), key=lambda item: item[1], reverse=True)),
                "processes": processes,
                "truncated": len(processes) >= self.ctx.limits.max_processes,
            }
        )
        if not processes:
            self.note_warning("no processes could be enumerated")
        elif inaccessible:
            self.note_warning(
                f"{inaccessible} process(es) had restricted details"
                + ("" if self.is_root else "; re-run as root for complete visibility")
            )

    # -- helpers -----------------------------------------------------------
    def _readlink_deleted(self, pid: int) -> bool:
        link = self.ctx.paths.proc / str(pid) / "exe"
        try:
            return os.readlink(link).endswith(" (deleted)")
        except OSError:
            return False

    def _path_roots(self) -> list[tuple[Path, str, str]]:
        paths = self.ctx.paths
        return [
            (paths.tmp, "temporary directory", "PROC_EXEC_FROM_TMP"),
            (paths.var_tmp, "temporary directory", "PROC_EXEC_FROM_TMP"),
            (paths.dev_shm, "/dev/shm", "PROC_EXEC_FROM_DEV_SHM"),
            (paths.run_shm, "/run/shm", "PROC_EXEC_FROM_DEV_SHM"),
            (paths.home, "user home directory", "PROC_EXEC_FROM_HOME"),
        ]

    def _inspect_process(self, record: dict[str, Any]) -> bool:
        """Emit findings for one process.  Returns True when anything fired."""
        pid = record["pid"]
        exe = record.get("exe") or ""
        cmdline = record.get("cmdline_str") or ""
        username = record.get("username")
        uid = record.get("uid")
        is_root_process = uid == 0 or username == "root"
        fired = False
        evidence_item = None

        def executable_evidence() -> Any:
            nonlocal evidence_item
            if evidence_item is None and exe:
                evidence_item = self.evidence_file(
                    self.ctx.paths.proc / str(pid) / "exe",
                    f"Executable image for PID {pid} ({record.get('name')}), original path {exe}",
                )
            return evidence_item

        matched_path: tuple[str, str] | None = None
        if exe:
            for root, label, rule_id in self._path_roots():
                try:
                    if Path(exe).resolve(strict=False).is_relative_to(root.resolve(strict=False)):
                        matched_path = (label, rule_id)
                        break
                except (OSError, ValueError):
                    continue

        if matched_path:
            label, rule_id = matched_path
            if is_root_process:
                rule_id = "PROC_ROOT_FROM_SUSPICIOUS_PATH"
            description = (
                f"PID {pid} ({record.get('name')!r}) runs as {username or uid} from the "
                f"{label}: {exe}"
            )
            if record.get("deleted_executable"):
                description += " (the executable has been deleted from disk)"
            self.add_finding(
                rule_id,
                description,
                details={
                    "pid": pid,
                    "ppid": record.get("ppid"),
                    "user": username,
                    "exe": exe,
                    "cmdline": cmdline,
                    "started": record.get("create_time"),
                },
                evidence=[item for item in [executable_evidence()] if item],
                confidence=Confidence.MEDIUM,
            )
            fired = True

        if record.get("deleted_executable"):
            self.add_finding(
                "PROC_DELETED_EXECUTABLE",
                f"PID {pid} ({record.get('name')!r}, user {username or uid}) is running from a deleted executable: {exe}",
                details={
                    "pid": pid,
                    "user": username,
                    "exe": exe,
                    "cmdline": cmdline,
                    "started": record.get("create_time"),
                },
                evidence=[item for item in [executable_evidence()] if item],
                confidence=Confidence.MEDIUM,
            )
            fired = True

        patterns = match_patterns(cmdline)
        if patterns:
            self.add_finding(
                "PROC_SUSPICIOUS_CMDLINE",
                f"PID {pid} ({record.get('name')!r}, user {username or uid}) command line matches: "
                + ", ".join(item["name"] for item in patterns),
                details={"pid": pid, "user": username, "cmdline": cmdline, "patterns": patterns},
                evidence=[item for item in [executable_evidence()] if item],
                confidence=Confidence.MEDIUM,
            )
            fired = True

        name = record.get("name") or ""
        if name and (name.startswith(".") or name != name.strip() or not any(char.isalnum() for char in name)):
            self.add_finding(
                "PROC_HIDDEN_NAME",
                f"PID {pid} has a disguised process name: {name!r} (executable {exe or 'unavailable'}).",
                details={"pid": pid, "name": name, "exe": exe, "cmdline": cmdline, "user": username},
                evidence=[item for item in [executable_evidence()] if item],
                confidence=Confidence.LOW,
            )
            fired = True

        if not exe and cmdline and self.is_root:
            self.add_finding(
                "PROC_NO_EXECUTABLE",
                f"PID {pid} ({name!r}, user {username or uid}) has a command line but no readable executable path.",
                details={"pid": pid, "name": name, "cmdline": cmdline, "user": username},
                confidence=Confidence.LOW,
            )
            fired = True

        if fired:
            self.evidence_data(
                f"/proc/{pid}/cmdline",
                {"pid": pid, "cmdline": cmdline, "exe": exe, "user": username},
                f"Command-line evidence for flagged PID {pid}",
            )
        return fired
