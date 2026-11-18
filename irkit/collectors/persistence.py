"""Persistence investigation collector.

Audits cron, systemd units, linker preload configuration, shell profiles,
rc.local, SSH rc scripts, at jobs and init scripts.  Everything is read-only;
nothing is disabled or removed.
"""

from __future__ import annotations

import os
import shlex
import stat
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

from irkit.accountparse import parse_passwd, parse_unit, unit_exec_lines
from irkit.collectors.base import BaseCollector
from irkit.models import Confidence
from irkit.patterns import match_patterns
from irkit.utils import file_metadata, iso_utc, iter_files, utc_now

_SUSPICIOUS_NAMES = {"ld.so.preload"}


class PersistenceCollector(BaseCollector):
    name = "persistence"
    description = "Cron, systemd, linker preload, profiles and startup persistence"
    requires_root = False

    def run(self) -> None:
        cron = self._cron()
        systemd = self._systemd()
        linker = self._linker()
        startup = self._startup_scripts()
        at_jobs = self._at_jobs()
        initd = self._initd()

        self.data.update(
            {
                "cron": cron,
                "systemd": systemd,
                "linker": linker,
                "startup": startup,
                "at_jobs": at_jobs,
                "initd": initd,
                "collected_at": iso_utc(),
            }
        )

    # -- shared helpers ----------------------------------------------------
    def _now(self) -> datetime:
        return utc_now()

    def _recent(self, mtime: float, days: int) -> bool:
        return mtime >= (self._now() - timedelta(days=days)).timestamp()

    def _suspicious_path(self, path: str) -> bool:
        """Return ``True`` only for absolute paths under attacker-writable trees.

        Bare command names (for example ``systemd-dissect``) are resolved through
        ``PATH`` at run time and must never be resolved against the collector's
        current working directory; doing so would flag every normal unit.
        """
        if not path or not path.startswith("/"):
            return False
        paths = self.ctx.paths
        try:
            candidate = Path(path).resolve(strict=False)
        except (OSError, ValueError):
            return False
        # When inspecting an offline image (``--root``), absolute paths inside
        # configuration files refer to the image, not to the running host, so
        # also test the same path rebased under the configured root.
        candidates = [candidate]
        if paths.root != Path("/"):
            try:
                candidates.append(paths.root / candidate.relative_to("/"))
            except ValueError:
                pass
        for candidate in candidates:
            for root in (paths.tmp, paths.var_tmp, paths.dev_shm, paths.run_shm, paths.home):
                try:
                    if candidate.is_relative_to(root.resolve(strict=False)):
                        return True
                except (OSError, ValueError):
                    continue
        return False

    @staticmethod
    def _first_executable(command: str) -> str:
        try:
            tokens = shlex.split(command, posix=True)
        except ValueError:
            tokens = command.split()
        for token in tokens:
            candidate = token.lstrip("-@+!:")
            if candidate.startswith("/"):
                return candidate
        return tokens[0] if tokens else ""

    def _read(self, path: Path, description: str, *, record: bool = True) -> str | None:
        return self.read_text(path, description, record=record, required=False)

    # -- cron --------------------------------------------------------------
    def _cron_files(self) -> list[tuple[Path, bool, str, str]]:
        """Return ``(path, is_system_file, default_user, schedule_hint)``."""
        files: list[tuple[Path, bool, str, str]] = []
        if self.ctx.paths.crontab.exists():
            files.append((self.ctx.paths.crontab, True, "root", ""))
        for directory in (self.ctx.paths.cron_d,):
            if directory.is_dir():
                try:
                    for entry in sorted(directory.iterdir()):
                        if entry.is_file() and not entry.is_symlink() and "." not in entry.name:
                            files.append((entry, True, "root", ""))
                except OSError as exc:
                    self.note_warning(f"cannot list {self.rel(directory)}: {exc}")
        for directory, hint in (
            (self.ctx.paths.cron_hourly, "@hourly"),
            (self.ctx.paths.cron_daily, "@daily"),
            (self.ctx.paths.cron_weekly, "@weekly"),
            (self.ctx.paths.cron_monthly, "@monthly"),
        ):
            if directory.is_dir():
                try:
                    for entry in sorted(directory.iterdir()):
                        if entry.is_file() and not entry.is_symlink():
                            files.append((entry, False, "root", hint))
                except OSError as exc:
                    self.note_warning(f"cannot list {self.rel(directory)}: {exc}")
        spool_dirs = [self.ctx.paths.spool_cron, self.ctx.paths.spool_cron_alt]
        seen: set[Path] = {path for path, _, _, _ in files}
        for spool in spool_dirs:
            if not spool.is_dir():
                continue
            try:
                entries = list(spool.iterdir())
            except OSError:
                continue
            for entry in entries:
                if entry.is_dir() or entry.is_symlink() or entry in seen:
                    continue
                if entry.name in {"atjobs", "atspool"}:
                    continue
                seen.add(entry)
                files.append((entry, False, entry.name, ""))
        return files

    def _cron(self) -> dict[str, Any]:
        files = self._cron_files()
        entries: list[dict[str, Any]] = []
        file_records: list[dict[str, Any]] = []
        threshold_days = self.ctx.config.thresholds.cron_recent_days

        for path, is_system, default_user, hint in files:
            text = self._read(path, f"Cron configuration ({path.name})")
            metadata = file_metadata(path)
            record: dict[str, Any] = {
                "path": self.rel(path),
                "is_system_file": is_system,
                "mtime": metadata.get("mtime"),
                "mode": metadata.get("mode"),
                "owner": metadata.get("owner"),
                "readable": text is not None,
                "entries": 0,
            }
            if text is None:
                file_records.append(record)
                continue
            if hint and not is_system:
                # cron.hourly/daily/weekly/monthly contain executable scripts,
                # not crontab syntax; treat the file as a single scheduled job.
                parsed = [
                    {
                        "source": self.rel(path),
                        "line_number": 0,
                        "schedule": hint,
                        "user": default_user,
                        "command": f"[script] {self.rel(path)}",
                        "patterns": match_patterns(text),
                    }
                ]
                env: list[str] = []
            else:
                parsed, env = self._parse_cron(text, is_system, default_user, hint, self.rel(path))
            record["entries"] = len(parsed)
            record["environment"] = env
            file_records.append(record)
            entries.extend(parsed)

            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = 0
            if mtime and self._recent(mtime, threshold_days):
                self.add_finding(
                    "PERS_CRON_RECENT",
                    f"Cron file {self.rel(path)} was modified at {iso_utc(mtime)}.",
                    details={"path": self.rel(path), "mtime": iso_utc(mtime), "entries": len(parsed)},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )

            for env_line in env:
                patterns = match_patterns(env_line)
                if patterns:
                    self.add_finding(
                        "PERS_CRON_SUSPICIOUS",
                        f"Cron environment in {self.rel(path)} matches: "
                        + ", ".join(item["name"] for item in patterns),
                        details={"path": self.rel(path), "line": env_line, "patterns": patterns},
                        evidence=[item for item in self.evidence if item.source_path == str(path)],
                        confidence=Confidence.MEDIUM,
                    )

            for entry in parsed:
                if not entry["patterns"]:
                    continue
                self.add_finding(
                    "PERS_CRON_SUSPICIOUS",
                    f"Cron job in {entry['source']} (user {entry['user']}, schedule {entry['schedule']}) "
                    f"matches: {', '.join(item['name'] for item in entry['patterns'])}",
                    details=entry,
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )

        if not files:
            self.note_warning("no cron files were found")
        return {
            "files": file_records,
            "entries": entries[:500],
            "entry_count": len(entries),
            "suspicious_entry_count": sum(1 for entry in entries if entry["patterns"]),
        }

    def _parse_cron(
        self,
        text: str,
        is_system: bool,
        default_user: str,
        hint: str,
        source: str,
    ) -> tuple[list[dict[str, Any]], list[str]]:
        entries: list[dict[str, Any]] = []
        env: list[str] = []
        for line_number, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if "=" in line and not line.startswith((" ", "\t")) and line.split("=", 1)[0].replace("_", "").isalnum():
                env.append(line)
                continue
            tokens = line.split()
            if not tokens:
                continue
            if tokens[0].startswith("@"):
                schedule = tokens[0]
                rest = tokens[1:]
            else:
                if len(tokens) < 6:
                    continue
                schedule = " ".join(tokens[:5])
                rest = tokens[5:]
            if is_system:
                if not rest:
                    continue
                user = rest[0]
                command = " ".join(rest[1:])
            else:
                user = default_user
                command = " ".join(rest)
            if hint and not is_system:
                schedule = schedule if schedule.startswith("@") else hint
            entries.append(
                {
                    "source": source,
                    "line_number": line_number,
                    "schedule": schedule,
                    "user": user,
                    "command": command,
                    "patterns": match_patterns(command),
                }
            )
        return entries, env

    # -- systemd -----------------------------------------------------------
    def _systemd_files(self) -> list[Path]:
        files: list[Path] = []
        seen: set[Path] = set()
        for directory in self.ctx.paths.systemd_unit_dirs:
            if not directory.is_dir():
                continue
            try:
                resolved = directory.resolve(strict=False)
            except OSError:
                resolved = directory
            if resolved in seen:
                continue
            seen.add(resolved)
            for path in iter_files(
                directory,
                max_depth=2,
                max_entries=4000,
                budget_seconds=20.0,
            ):
                if path.suffix in {".service", ".timer", ".socket"} or (
                    path.suffix == ".conf" and path.parent.name.endswith(".d")
                ):
                    files.append(path)
        return files

    def _systemd(self) -> dict[str, Any]:
        files = self._systemd_files()
        units: list[dict[str, Any]] = []
        recent_threshold = self.ctx.config.thresholds.systemd_recent_days
        for path in files:
            text = self._read(path, f"Systemd unit ({path.name})")
            if text is None:
                continue
            sections = parse_unit(text)
            service = sections.get("Service", {})
            install = sections.get("Install", {})
            timer = sections.get("Timer", {})
            execs = [{"key": key, "command": command} for key, command in unit_exec_lines(sections)]
            metadata = file_metadata(path)
            suspicious = []
            for exec_item in execs:
                executable = self._first_executable(exec_item["command"])
                patterns = match_patterns(exec_item["command"])
                if self._suspicious_path(executable) or patterns:
                    suspicious.append(
                        {
                            "directive": exec_item["key"],
                            "command": exec_item["command"],
                            "executable": executable,
                            "patterns": patterns,
                            "writable_path": self._suspicious_path(executable),
                        }
                    )
            under_etc = self.ctx.paths.systemd_system_units in path.parents or path == self.ctx.paths.systemd_system_units
            unit = {
                "path": self.rel(path),
                "name": path.name,
                "kind": path.suffix.lstrip("."),
                "mtime": metadata.get("mtime"),
                "description": (sections.get("Unit", {}).get("Description") or [""])[0],
                "user": (service.get("User") or [None])[0],
                "exec": execs,
                "wanted_by": install.get("WantedBy", []),
                "on_calendar": timer.get("OnCalendar", []),
                "suspicious": suspicious,
                "recent": False,
            }
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = 0
            if mtime and under_etc and self._recent(mtime, recent_threshold):
                unit["recent"] = True
                self.add_finding(
                    "PERS_SYSTEMD_RECENT",
                    f"Systemd unit {self.rel(path)} was created or modified at {iso_utc(mtime)}.",
                    details={"path": self.rel(path), "mtime": iso_utc(mtime), "kind": unit["kind"]},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
            if suspicious:
                self.add_finding(
                    "PERS_SYSTEMD_SUSPICIOUS_EXEC",
                    f"Systemd unit {self.rel(path)} executes a suspicious command: "
                    + "; ".join(item["command"] for item in suspicious[:3]),
                    details={"path": self.rel(path), "suspicious": suspicious, "user": unit["user"]},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
            units.append(unit)

        user_units = self._user_units()
        if not files:
            self.note_warning("no systemd unit files were found")
        return {
            "units": units[:1000],
            "unit_count": len(units),
            "suspicious_unit_count": sum(1 for unit in units if unit["suspicious"]),
            "user_units": user_units,
        }

    def _user_units(self) -> list[dict[str, Any]]:
        accounts = self._accounts()
        results: list[dict[str, Any]] = []
        for account in accounts:
            home_value = str(account.get("home") or "")
            if not home_value.startswith("/"):
                continue
            home = self.ctx.paths.root / home_value.lstrip("/")
            if not home.is_dir():
                continue
            for directory in self.ctx.paths.user_systemd_dirs(home):
                if not directory.is_dir():
                    continue
                found: list[dict[str, Any]] = []
                for path in iter_files(directory, max_depth=2, max_entries=200, budget_seconds=5.0):
                    if path.suffix not in {".service", ".timer", ".socket"}:
                        continue
                    text = self._read(path, f"User systemd unit ({account.get('name')}/{path.name})")
                    sections = parse_unit(text) if text else {}
                    execs = [{"key": key, "command": command} for key, command in unit_exec_lines(sections)]
                    suspicious = []
                    for exec_item in execs:
                        executable = self._first_executable(exec_item["command"])
                        patterns = match_patterns(exec_item["command"])
                        if self._suspicious_path(executable) or patterns:
                            suspicious.append(
                                {
                                    "directive": exec_item["key"],
                                    "command": exec_item["command"],
                                    "executable": executable,
                                    "patterns": patterns,
                                    "writable_path": self._suspicious_path(executable),
                                }
                            )
                    found.append({"path": self.rel(path), "exec": execs, "suspicious": suspicious})
                    if suspicious:
                        self.add_finding(
                            "PERS_SYSTEMD_SUSPICIOUS_EXEC",
                            f"User systemd unit {self.rel(path)} for {account.get('name')} executes a "
                            f"suspicious command: {suspicious[0]['command']}",
                            details={"path": self.rel(path), "account": account.get("name"), "suspicious": suspicious},
                            evidence=[item for item in self.evidence if item.source_path == str(path)],
                            confidence=Confidence.MEDIUM,
                        )
                if found:
                    results.append({"account": account.get("name"), "directory": self.rel(directory), "units": found})
                    self.add_finding(
                        "PERS_USER_SYSTEMD_UNIT",
                        f"{len(found)} user systemd unit(s) exist for {account.get('name')} in {self.rel(directory)}.",
                        details={"account": account.get("name"), "units": found},
                        evidence=[
                            item
                            for item in self.evidence
                            if item.source_path and item.source_path.startswith(str(directory))
                        ],
                        confidence=Confidence.HIGH,
                    )
        return results

    def _accounts(self) -> list[dict[str, Any]]:
        text = self._read(self.ctx.paths.passwd, "Account database (for persistence discovery)", record=False)
        accounts: list[dict[str, Any]] = []
        if text:
            for account in parse_passwd(text):
                accounts.append({"name": account.name, "home": account.home, "uid": account.uid})
        if not any(item["name"] == "root" for item in accounts):
            accounts.append({"name": "root", "home": "/root", "uid": 0})
        return accounts

    # -- linker preload ----------------------------------------------------
    def _linker(self) -> dict[str, Any]:
        preload_path = self.ctx.paths.ld_preload
        preload: dict[str, Any] = {"present": preload_path.exists(), "entries": [], "content": None}
        if preload_path.exists():
            text = self._read(preload_path, "Dynamic linker preload configuration")
            metadata = file_metadata(preload_path)
            lines = [
                line.strip()
                for line in (text or "").splitlines()
                if line.strip() and not line.strip().startswith("#")
            ]
            preload.update({"entries": lines, "content": text, "mtime": metadata.get("mtime"), "mode": metadata.get("mode")})
            if lines:
                self.add_finding(
                    "PERS_LD_PRELOAD",
                    f"/etc/ld.so.preload exists and references {len(lines)} shared object(s): "
                    + ", ".join(lines[:10]),
                    details={"path": self.rel(preload_path), "entries": lines, "mtime": metadata.get("mtime")},
                    evidence=[item for item in self.evidence if item.source_path == str(preload_path)],
                    confidence=Confidence.HIGH,
                )

        conf_files: list[Path] = []
        if self.ctx.paths.ld_so_conf.exists():
            conf_files.append(self.ctx.paths.ld_so_conf)
        conf_dir = self.ctx.paths.etc / "ld.so.conf.d"
        if conf_dir.is_dir():
            try:
                conf_files.extend(sorted(entry for entry in conf_dir.glob("*.conf") if entry.is_file()))
            except OSError:
                pass
        conf_records: list[dict[str, Any]] = []
        for path in conf_files:
            text = self._read(path, f"Dynamic linker search path ({path.name})")
            if text is None:
                continue
            suspicious = [
                line.strip()
                for line in text.splitlines()
                if line.strip().startswith("/") and self._suspicious_path(line.strip())
            ]
            conf_records.append({"path": self.rel(path), "suspicious_paths": suspicious})
            if suspicious:
                self.add_finding(
                    "PERS_LD_SO_CONF_SUSPICIOUS",
                    f"Linker configuration {self.rel(path)} references writable path(s): {', '.join(suspicious)}",
                    details={"path": self.rel(path), "paths": suspicious},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
        return {"preload": preload, "config_files": conf_records}

    # -- startup scripts ---------------------------------------------------
    def _startup_scripts(self) -> dict[str, Any]:
        results: dict[str, Any] = {"rc_local": None, "profiles": [], "sshrc": []}

        rc_local = self.ctx.paths.rc_local
        if rc_local.exists():
            text = self._read(rc_local, "rc.local startup script")
            metadata = file_metadata(rc_local)
            patterns = match_patterns(text or "")
            results["rc_local"] = {
                "path": self.rel(rc_local),
                "mtime": metadata.get("mtime"),
                "mode": metadata.get("mode"),
                "patterns": patterns,
            }
            if patterns:
                self.add_finding(
                    "PERS_RC_LOCAL_SUSPICIOUS",
                    f"rc.local contains patterns: {', '.join(item['name'] for item in patterns)}",
                    details={"path": self.rel(rc_local), "patterns": patterns},
                    evidence=[item for item in self.evidence if item.source_path == str(rc_local)],
                    confidence=Confidence.MEDIUM,
                )

        profile_files: list[Path] = [self.ctx.paths.profile, self.ctx.paths.bashrc]
        if self.ctx.paths.profile_d.is_dir():
            try:
                profile_files.extend(sorted(self.ctx.paths.profile_d.glob("*.sh")))
            except OSError:
                pass
        for account in self._accounts():
            home_value = str(account.get("home") or "")
            if not home_value.startswith("/"):
                continue
            home = self.ctx.paths.root / home_value.lstrip("/")
            for name in (".bashrc", ".bash_profile", ".profile", ".bash_login", ".zshrc"):
                candidate = home / name
                if candidate.is_file() and not candidate.is_symlink():
                    profile_files.append(candidate)
        seen: set[Path] = set()
        for path in profile_files:
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            if len(seen) > 300:
                self.note_warning("profile scan truncated at 300 files")
                break
            text = self._read(path, f"Shell profile ({path.name})")
            if text is None:
                continue
            patterns = match_patterns(text)
            if patterns:
                results["profiles"].append({"path": self.rel(path), "patterns": patterns})
                self.add_finding(
                    "PERS_PROFILE_SUSPICIOUS",
                    f"Shell profile {self.rel(path)} contains patterns: "
                    + ", ".join(item["name"] for item in patterns),
                    details={"path": self.rel(path), "patterns": patterns},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )

        sshrc_files: list[Path] = [self.ctx.paths.ssh_dir / "sshrc"]
        for account in self._accounts():
            home_value = str(account.get("home") or "")
            if home_value.startswith("/"):
                sshrc_files.append(self.ctx.paths.root / home_value.lstrip("/") / ".ssh" / "rc")
        for path in sshrc_files:
            if not path.is_file():
                continue
            text = self._read(path, "SSH login rc script")
            if text is None:
                continue
            patterns = match_patterns(text)
            results["sshrc"].append({"path": self.rel(path), "patterns": patterns})
            if patterns:
                self.add_finding(
                    "PERS_SSH_RC_SUSPICIOUS",
                    f"SSH rc script {self.rel(path)} contains patterns: "
                    + ", ".join(item["name"] for item in patterns),
                    details={"path": self.rel(path), "patterns": patterns},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
        return results

    # -- at jobs / init scripts -------------------------------------------
    def _at_jobs(self) -> dict[str, Any]:
        directories = [self.ctx.paths.at_jobs, self.ctx.paths.var / "spool" / "at"]
        jobs: list[dict[str, Any]] = []
        for directory in directories:
            if not directory.is_dir():
                continue
            try:
                entries = sorted(entry for entry in directory.iterdir() if entry.is_file())
            except OSError as exc:
                self.note_warning(f"cannot list at spool {self.rel(directory)}: {exc}")
                continue
            for entry in entries:
                metadata = file_metadata(entry)
                text = self._read(entry, f"Scheduled at job ({entry.name})", record=False)
                patterns = match_patterns(text or "")
                jobs.append(
                    {
                        "path": self.rel(entry),
                        "mtime": metadata.get("mtime"),
                        "owner": metadata.get("owner"),
                        "patterns": patterns,
                    }
                )
                self.evidence_file(entry, f"Scheduled at job ({entry.name})")
        if jobs:
            self.add_finding(
                "PERS_AT_JOB",
                f"{len(jobs)} scheduled at job(s) exist in the at spool.",
                details={"count": len(jobs), "jobs": jobs[:50]},
                evidence=[item for item in self.evidence if "/at" in item.source_path],
                confidence=Confidence.MEDIUM,
            )
        return {"jobs": jobs, "count": len(jobs)}

    def _initd(self) -> dict[str, Any]:
        records: list[dict[str, Any]] = []
        directory = self.ctx.paths.init_d
        if not directory.is_dir():
            return {"scripts": records, "count": 0}
        try:
            entries = sorted(entry for entry in directory.iterdir() if entry.is_file() and not entry.is_symlink())
        except OSError as exc:
            self.note_warning(f"cannot list /etc/init.d: {exc}")
            return {"scripts": records, "count": 0}
        threshold_days = self.ctx.config.thresholds.systemd_recent_days
        for path in entries:
            text = self._read(path, f"Init script ({path.name})")
            metadata = file_metadata(path)
            patterns = match_patterns(text or "")
            records.append({"path": self.rel(path), "mtime": metadata.get("mtime"), "patterns": patterns})
            try:
                mtime = path.stat().st_mtime
            except OSError:
                mtime = 0
            if mtime and self._recent(mtime, threshold_days):
                self.add_finding(
                    "PERS_INITD_RECENT",
                    f"Init script {self.rel(path)} was modified at {iso_utc(mtime)}.",
                    details={"path": self.rel(path), "mtime": iso_utc(mtime)},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
            if patterns:
                self.add_finding(
                    "PERS_INITD_SUSPICIOUS",
                    f"Init script {self.rel(path)} contains patterns: "
                    + ", ".join(item["name"] for item in patterns),
                    details={"path": self.rel(path), "patterns": patterns},
                    evidence=[item for item in self.evidence if item.source_path == str(path)],
                    confidence=Confidence.MEDIUM,
                )
        return {"scripts": records, "count": len(records)}
