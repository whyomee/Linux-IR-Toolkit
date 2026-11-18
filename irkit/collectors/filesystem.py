"""Filesystem investigation collector.

Looks for recent security-configuration changes, world-writable sensitive
files, SUID/SGID anomalies, executables in temporary directories and hidden
payloads.  Traversal is bounded by depth, entry count and wall-clock budget.
"""

from __future__ import annotations

import os
import stat
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

from irkit.collectors.base import BaseCollector
from irkit.models import Confidence
from irkit.utils import file_metadata, iso_utc, iter_files, mode_to_rwx, utc_now

_STANDARD_SUID_RELATIVE = (
    ("bin",),
    ("sbin",),
    ("usr", "bin"),
    ("usr", "sbin"),
    ("usr", "lib"),
    ("usr", "libexec"),
    ("lib",),
    ("lib64",),
    ("usr", "lib64"),
)


class FilesystemCollector(BaseCollector):
    name = "filesystem"
    description = "SUID/SGID anomalies, writable configs, temp-dir executables and recent changes"
    requires_root = False

    def run(self) -> None:
        started = time.monotonic()
        sensitive = self._sensitive_files()
        world_writable = self._world_writable(sensitive)
        recent = self._recent_config_changes(sensitive)
        suid = self._suid_scan()
        temp = self._temp_scan()
        self.data.update(
            {
                "sensitive_files": sensitive,
                "world_writable": world_writable,
                "recent_config_changes": recent,
                "suid": suid,
                "temporary_directories": temp,
                "scan_duration_ms": int((time.monotonic() - started) * 1000),
                "collected_at": iso_utc(),
            }
        )

    # -- helpers -----------------------------------------------------------
    @staticmethod
    def _under(path: Path, root: Path) -> bool:
        try:
            return path.resolve(strict=False).is_relative_to(root.resolve(strict=False))
        except (OSError, ValueError):
            return False

    def _evidence_for(self, path: Path) -> list[Any]:
        return [item for item in self.evidence if item.source_path == str(path)]

    def _standard_suid_dirs(self) -> tuple[Path, ...]:
        """Package-managed binary directories, rooted at the collection root."""
        return tuple(self.ctx.paths.p(*parts) for parts in _STANDARD_SUID_RELATIVE)

    def _sensitive_files(self) -> list[dict[str, Any]]:
        paths = self.ctx.paths
        files: list[Path] = [
            paths.passwd,
            paths.passwd_backup,
            paths.shadow,
            paths.group,
            paths.gshadow,
            paths.sudoers,
            paths.crontab,
            paths.ld_preload,
            paths.ld_so_conf,
            paths.sshd_config,
            paths.profile,
            paths.bashrc,
            paths.login_defs,
            paths.fstab,
        ]
        directories = [
            paths.sudoers_d,
            paths.sshd_config_d,
            paths.cron_d,
            paths.systemd_system_units,
            paths.etc / "ld.so.conf.d",
            paths.etc / "pam.d",
            paths.etc / "security",
            paths.profile_d,
            paths.init_d,
        ]
        for directory in directories:
            if not directory.is_dir():
                continue
            try:
                entries = sorted(directory.iterdir())
            except OSError:
                continue
            for entry in entries[:500]:
                if entry.is_file() or entry.is_symlink():
                    files.append(entry)

        records: list[dict[str, Any]] = []
        seen: set[Path] = set()
        for path in files:
            if path in seen:
                continue
            seen.add(path)
            if not path.exists():
                continue
            metadata = file_metadata(path)
            if "error" in metadata:
                continue
            # Password databases are recorded by metadata only; their content is
            # never hashed or copied into evidence.
            sensitive_secret = path.name in {"shadow", "shadow-", "gshadow", "gshadow-"}
            self.evidence_file(
                path,
                f"Security-sensitive file ({path.name})",
                hash_content=not sensitive_secret,
            )
            records.append(
                {
                    "path": self.rel(path),
                    "absolute_path": str(path),
                    "mode": metadata.get("mode"),
                    "mode_octal": metadata.get("mode_octal"),
                    "owner": metadata.get("owner"),
                    "group": metadata.get("group"),
                    "mtime": metadata.get("mtime"),
                    "size": metadata.get("size"),
                    "world_writable": metadata.get("is_world_writable", False),
                }
            )
        return records

    def _world_writable(self, sensitive: list[dict[str, Any]]) -> dict[str, Any]:
        findings: list[dict[str, Any]] = []
        for record in sensitive:
            path = Path(record["absolute_path"])
            # A symlink's own mode is meaningless on Linux (always lrwxrwxrwx) and
            # masked units commonly point at /dev/null, which is world-writable.
            # Only regular files can be genuinely world-writable configuration.
            if path.is_symlink():
                continue
            try:
                info = path.stat()
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            if info.st_mode & stat.S_IWOTH:
                findings.append(record)
                self.add_finding(
                    "FS_WORLD_WRITABLE_SENSITIVE",
                    f"{record['path']} is world-writable ({mode_to_rwx(info.st_mode)}, owner {record['owner']}).",
                    details=record,
                    evidence=self._evidence_for(path),
                    confidence=Confidence.HIGH,
                )

        directories: list[dict[str, Any]] = []
        etc = self.ctx.paths.etc
        if etc.is_dir():
            candidates: list[Path] = [etc]
            try:
                candidates.extend(sorted(entry for entry in etc.iterdir() if entry.is_dir() and not entry.is_symlink()))
            except OSError:
                pass
            for directory in candidates[:500]:
                try:
                    info = directory.stat()
                except OSError:
                    continue
                if not stat.S_ISDIR(info.st_mode):
                    continue
                if info.st_mode & stat.S_IWOTH and not info.st_mode & stat.S_ISVTX:
                    record = {
                        "path": self.rel(directory),
                        "mode": mode_to_rwx(info.st_mode),
                        "mode_octal": oct(stat.S_IMODE(info.st_mode)),
                        "owner": str(info.st_uid),
                    }
                    directories.append(record)
                    self.add_finding(
                        "FS_WORLD_WRITABLE_ETC_DIR",
                        f"Directory {record['path']} is world-writable without the sticky bit "
                        f"({record['mode_octal']}).",
                        details=record,
                        confidence=Confidence.HIGH,
                    )
        return {"files": findings, "directories": directories}

    def _recent_config_changes(self, sensitive: list[dict[str, Any]]) -> list[dict[str, Any]]:
        threshold = utc_now() - timedelta(days=self.ctx.config.thresholds.recent_config_days)
        recent: list[dict[str, Any]] = []
        for record in sensitive:
            try:
                mtime = Path(record["absolute_path"]).stat().st_mtime
            except OSError:
                continue
            if mtime < threshold.timestamp():
                continue
            recent.append(record)
            self.add_finding(
                "FS_RECENT_SECURITY_CONFIG_CHANGE",
                f"{record['path']} was modified at {iso_utc(mtime)} (within "
                f"{self.ctx.config.thresholds.recent_config_days} days).",
                details={**record, "mtime_epoch": mtime},
                evidence=self._evidence_for(Path(record["absolute_path"])),
                confidence=Confidence.MEDIUM,
            )
        return recent

    def _suid_scan(self) -> dict[str, Any]:
        deadline = time.monotonic() + 30.0
        records: list[dict[str, Any]] = []
        truncated = False
        for root in self.ctx.paths.suid_scan_roots:
            if not root.exists():
                continue
            remaining = max(1.0, min(15.0, deadline - time.monotonic()))
            if remaining <= 1.0:
                truncated = True
                break
            for path in iter_files(
                root,
                max_depth=8,
                max_entries=max(1000, self.ctx.limits.max_filesystem_entries // 2),
                budget_seconds=remaining,
            ):
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if not info.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    continue
                record = {
                    "path": self.rel(path),
                    "absolute_path": str(path),
                    "mode": mode_to_rwx(info.st_mode),
                    "mode_octal": oct(stat.S_IMODE(info.st_mode)),
                    "owner": str(info.st_uid),
                    "mtime": iso_utc(info.st_mtime),
                    "suid": bool(info.st_mode & stat.S_ISUID),
                    "sgid": bool(info.st_mode & stat.S_ISGID),
                }
                records.append(record)
                writable_dir = any(
                    self._under(path, root_path)
                    for root_path in (
                        self.ctx.paths.tmp,
                        self.ctx.paths.var_tmp,
                        self.ctx.paths.dev_shm,
                        self.ctx.paths.home,
                    )
                )
                standard_dir = any(self._under(path, root_path) for root_path in self._standard_suid_dirs())
                if writable_dir:
                    self.add_finding(
                        "FS_SUID_IN_WRITABLE_DIR",
                        f"SUID/SGID binary {self.rel(path)} resides in a writable directory "
                        f"({record['mode']}, owner {record['owner']}).",
                        details=record,
                        evidence=[self.evidence_file(path, f"SUID/SGID binary ({path.name})")],
                        confidence=Confidence.HIGH,
                    )
                elif not standard_dir:
                    self.add_finding(
                        "FS_SUID_UNEXPECTED",
                        f"SUID/SGID binary {self.rel(path)} is outside standard system directories "
                        f"({record['mode']}, owner {record['owner']}).",
                        details=record,
                        evidence=[self.evidence_file(path, f"SUID/SGID binary ({path.name})")],
                        confidence=Confidence.MEDIUM,
                    )
                if len(records) >= 2000:
                    truncated = True
                    break
            if len(records) >= 2000:
                break
        if truncated:
            self.note_warning("SUID/SGID scan was truncated by the entry or time budget")
        return {"files": records, "count": len(records), "truncated": truncated}

    def _temp_scan(self) -> dict[str, Any]:
        deadline = time.monotonic() + 30.0
        records: list[dict[str, Any]] = []
        roots: dict[str, dict[str, Any]] = {}
        hash_budget = 200
        truncated = False
        for root in self.ctx.paths.tmp_scan_roots:
            if not root.exists():
                continue
            root_record = {"path": self.rel(root), "files": 0, "executables": 0, "truncated": False}
            remaining = max(1.0, min(12.0, deadline - time.monotonic()))
            if remaining <= 1.0:
                truncated = True
                root_record["truncated"] = True
                roots[self.rel(root)] = root_record
                continue
            for path in iter_files(
                root,
                max_depth=4,
                max_entries=max(1000, self.ctx.limits.max_filesystem_entries // 2),
                budget_seconds=remaining,
            ):
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                executable = bool(info.st_mode & 0o111)
                hidden = path.name.startswith(".") or path.name != path.name.strip()
                record = {
                    "path": self.rel(path),
                    "absolute_path": str(path),
                    "size": info.st_size,
                    "mode": mode_to_rwx(info.st_mode),
                    "mode_octal": oct(stat.S_IMODE(info.st_mode)),
                    "owner": str(info.st_uid),
                    "mtime": iso_utc(info.st_mtime),
                    "executable": executable,
                    "hidden": hidden,
                    "world_writable": bool(info.st_mode & stat.S_IWOTH),
                }
                records.append(record)
                root_record["files"] += 1
                if executable:
                    root_record["executables"] += 1
                    evidence = None
                    if hash_budget > 0:
                        hash_budget -= 1
                        evidence = self.evidence_file(path, f"Executable in {self.rel(root)} ({path.name})")
                    if root == self.ctx.paths.dev_shm:
                        rule_id = "FS_DEV_SHM_EXEC"
                    elif hidden:
                        rule_id = "FS_HIDDEN_EXEC_IN_TMP"
                    else:
                        rule_id = "FS_EXEC_IN_TMP"
                    self.add_finding(
                        rule_id,
                        f"Executable {self.rel(path)} exists in {self.rel(root)} "
                        f"({record['mode']}, owner {record['owner']}, modified {record['mtime']}).",
                        details=record,
                        evidence=[item for item in [evidence] if item],
                        confidence=Confidence.MEDIUM,
                    )
                if len(records) >= 3000:
                    truncated = True
                    root_record["truncated"] = True
                    break
            roots[self.rel(root)] = root_record
            if len(records) >= 3000:
                break
        if truncated:
            self.note_warning("temporary-directory scan was truncated by the entry or time budget")
        records.sort(key=lambda item: item["mtime"], reverse=True)
        return {
            "roots": roots,
            "files": records[:1000],
            "file_count": len(records),
            "executable_count": sum(1 for record in records if record["executable"]),
            "truncated": truncated,
        }
