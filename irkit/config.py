"""Static configuration, limits and filesystem path resolution.

Every path used by a collector is derived from :class:`SystemPaths`.  The
default root is ``/``; tests point the root at a temporary directory, which
makes the whole toolkit unit-testable without touching the host.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

TOOL_NAME = "Linux-IR-Toolkit"
TOOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
EVIDENCE_SCHEMA = f"linux-ir-toolkit/evidence/v{SCHEMA_VERSION}"

DEFAULT_OUTPUT_DIR = "reports"

#: Directories that are never walked by the filesystem collector.
PSEUDO_FILESYSTEMS = frozenset(
    {
        "proc",
        "sysfs",
        "sys",
        "devtmpfs",
        "devpts",
        "cgroup",
        "cgroup2",
        "tracefs",
        "debugfs",
        "securityfs",
        "pstore",
        "bpf",
        "mqueue",
        "hugetlbfs",
        "configfs",
        "fusectl",
        "overlay",
        "squashfs",
        "nsfs",
        "autofs",
        "binfmt_misc",
        "rpc_pipefs",
    }
)

#: Filesystem types that are not useful for disk-usage style reporting.
VIRTUAL_FILESYSTEMS = PSEUDO_FILESYSTEMS | frozenset(
    {"tmpfs", "ramfs", "fuse.gvfsd-fuse", "fuse.portal", "fuse.snapfuse"}
)


@dataclass(frozen=True)
class Limits:
    """Hard safety limits so collection cannot exhaust memory or hang."""

    max_read_bytes: int = 4 * 1024 * 1024
    max_hash_bytes: int = 256 * 1024 * 1024
    max_log_lines: int = 200_000
    max_log_files: int = 6
    max_processes: int = 10_000
    max_filesystem_entries: int = 25_000
    max_evidence_items: int = 2_000
    max_findings_per_rule: int = 100
    command_timeout: int = 20
    scan_time_budget_seconds: float = 90.0
    max_json_details_chars: int = 4_000
    max_authorized_key_files: int = 200


@dataclass(frozen=True)
class Thresholds:
    """Detection thresholds.  Tuned to be conservative, not noisy."""

    ssh_failures_per_ip: int = 10
    ssh_failures_total: int = 50
    ssh_success_after_failures: int = 5
    recent_account_days: int = 30
    recent_file_hours: int = 24
    recent_config_days: int = 7
    cron_recent_days: int = 14
    systemd_recent_days: int = 14
    authorized_key_recent_days: int = 30


@dataclass(frozen=True)
class SystemPaths:
    """Resolved locations of the artifacts the toolkit inspects.

    ``root`` exists to make the collectors testable.  Production use leaves it
    at ``/``.  Note that process enumeration via psutil always observes the
    *live* host; only file-based collectors honour ``root``.
    """

    root: Path = Path("/")

    def p(self, *parts: str | Path) -> Path:
        """Join ``parts`` under the configured root."""
        return self.root.joinpath(*parts)

    # -- core system -----------------------------------------------------
    @property
    def etc(self) -> Path:
        return self.p("etc")

    @property
    def proc(self) -> Path:
        return self.p("proc")

    @property
    def sys(self) -> Path:
        return self.p("sys")

    @property
    def dev(self) -> Path:
        return self.p("dev")

    @property
    def run(self) -> Path:
        return self.p("run")

    @property
    def var(self) -> Path:
        return self.p("var")

    @property
    def home(self) -> Path:
        return self.p("home")

    @property
    def var_log(self) -> Path:
        return self.p("var", "log")

    @property
    def journal_dir(self) -> Path:
        return self.var_log / "journal"

    # -- identity / accounts ---------------------------------------------
    @property
    def passwd(self) -> Path:
        return self.etc / "passwd"

    @property
    def passwd_backup(self) -> Path:
        return self.etc / "passwd-"

    @property
    def shadow(self) -> Path:
        return self.etc / "shadow"

    @property
    def group(self) -> Path:
        return self.etc / "group"

    @property
    def gshadow(self) -> Path:
        return self.etc / "gshadow"

    @property
    def login_defs(self) -> Path:
        return self.etc / "login.defs"

    @property
    def sudoers(self) -> Path:
        return self.etc / "sudoers"

    @property
    def sudoers_d(self) -> Path:
        return self.etc / "sudoers.d"

    # -- host identity ----------------------------------------------------
    @property
    def os_release(self) -> Path:
        return self.etc / "os-release"

    @property
    def hostname_file(self) -> Path:
        return self.etc / "hostname"

    @property
    def fstab(self) -> Path:
        return self.etc / "fstab"

    @property
    def proc_version(self) -> Path:
        return self.proc / "version"

    @property
    def proc_cmdline(self) -> Path:
        return self.proc / "cmdline"

    @property
    def kernel_taint(self) -> Path:
        return self.proc / "sys" / "kernel" / "tainted"

    @property
    def selinux_enforce(self) -> Path:
        return self.sys / "fs" / "selinux" / "enforce"

    @property
    def apparmor_profiles(self) -> Path:
        return self.sys / "kernel" / "security" / "apparmor" / "profiles"

    # -- persistence -------------------------------------------------------
    @property
    def crontab(self) -> Path:
        return self.etc / "crontab"

    @property
    def cron_d(self) -> Path:
        return self.etc / "cron.d"

    @property
    def cron_daily(self) -> Path:
        return self.etc / "cron.daily"

    @property
    def cron_hourly(self) -> Path:
        return self.etc / "cron.hourly"

    @property
    def cron_weekly(self) -> Path:
        return self.etc / "cron.weekly"

    @property
    def cron_monthly(self) -> Path:
        return self.etc / "cron.monthly"

    @property
    def spool_cron(self) -> Path:
        return self.var / "spool" / "cron" / "crontabs"

    @property
    def spool_cron_alt(self) -> Path:
        return self.var / "spool" / "cron"

    @property
    def at_jobs(self) -> Path:
        return self.var / "spool" / "cron" / "atjobs"

    @property
    def systemd_system_units(self) -> Path:
        return self.etc / "systemd" / "system"

    @property
    def systemd_user_units(self) -> Path:
        return self.etc / "systemd" / "user"

    @property
    def ld_preload(self) -> Path:
        return self.etc / "ld.so.preload"

    @property
    def ld_so_conf(self) -> Path:
        return self.etc / "ld.so.conf"

    @property
    def rc_local(self) -> Path:
        return self.etc / "rc.local"

    @property
    def init_d(self) -> Path:
        return self.etc / "init.d"

    @property
    def profile(self) -> Path:
        return self.etc / "profile"

    @property
    def bashrc(self) -> Path:
        return self.etc / "bash.bashrc"

    @property
    def profile_d(self) -> Path:
        return self.etc / "profile.d"

    # -- ssh ---------------------------------------------------------------
    @property
    def ssh_dir(self) -> Path:
        return self.etc / "ssh"

    @property
    def sshd_config(self) -> Path:
        return self.ssh_dir / "sshd_config"

    @property
    def sshd_config_d(self) -> Path:
        return self.ssh_dir / "sshd_config.d"

    # -- filesystem scan ---------------------------------------------------
    @property
    def tmp(self) -> Path:
        return self.p("tmp")

    @property
    def var_tmp(self) -> Path:
        return self.var / "tmp"

    @property
    def dev_shm(self) -> Path:
        return self.dev / "shm"

    @property
    def run_shm(self) -> Path:
        return self.run / "shm"

    @property
    def binary_dirs(self) -> tuple[Path, ...]:
        return (
            self.p("bin"),
            self.p("sbin"),
            self.p("usr", "bin"),
            self.p("usr", "sbin"),
            self.p("usr", "local", "bin"),
            self.p("usr", "local", "sbin"),
        )

    @property
    def suid_scan_roots(self) -> tuple[Path, ...]:
        """Roots walked when looking for SUID/SGID binaries."""
        return (
            *self.binary_dirs,
            self.p("usr", "lib"),
            self.p("usr", "libexec"),
            self.p("opt"),
            self.tmp,
            self.var_tmp,
            self.dev_shm,
            self.home,
        )

    @property
    def tmp_scan_roots(self) -> tuple[Path, ...]:
        return (self.tmp, self.var_tmp, self.dev_shm, self.run_shm)

    @property
    def systemd_unit_dirs(self) -> tuple[Path, ...]:
        """System unit directories, ordered by systemd precedence."""
        return (
            self.etc / "systemd" / "system",
            self.run / "systemd" / "system",
            self.p("usr", "lib", "systemd", "system"),
            self.p("lib", "systemd", "system"),
        )

    def user_systemd_dirs(self, home_dir: Path) -> tuple[Path, ...]:
        return (
            home_dir / ".config" / "systemd" / "user",
            home_dir / ".local" / "share" / "systemd" / "user",
        )

    # -- logs --------------------------------------------------------------
    def log_candidates(self, patterns: Sequence[str]) -> list[Path]:
        """Return existing log files matching glob ``patterns`` under /var/log.

        Rotated files (``.1``, ``.2.gz``) are included; the caller is expected
        to cap the number of files it reads.
        """
        found: list[Path] = []
        for pattern in patterns:
            for candidate in sorted(self.var_log.glob(pattern)):
                if candidate.is_file() and not candidate.is_symlink():
                    if candidate not in found:
                        found.append(candidate)
        return found

    # -- helpers -----------------------------------------------------------
    def existing(self, paths: Iterable[Path]) -> list[Path]:
        """Return the subset of ``paths`` that currently exist."""
        return [path for path in paths if path.exists()]

    def rel(self, path: Path) -> str:
        """Render ``path`` relative to the configured root, for reports."""
        try:
            return "/" + str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    @classmethod
    def from_root(cls, root: str | os.PathLike[str]) -> "SystemPaths":
        return cls(root=Path(root).resolve())


@dataclass(frozen=True)
class ToolkitConfig:
    """Runtime configuration shared by all collectors."""

    paths: SystemPaths = field(default_factory=SystemPaths)
    limits: Limits = field(default_factory=Limits)
    thresholds: Thresholds = field(default_factory=Thresholds)
    redact_output: bool = True
    ioc_indicators: tuple[dict, ...] = ()
    ioc_source: str | None = None

    def with_iocs(self, indicators: Sequence[dict], source: str | None) -> "ToolkitConfig":
        return ToolkitConfig(
            paths=self.paths,
            limits=self.limits,
            thresholds=self.thresholds,
            redact_output=self.redact_output,
            ioc_indicators=tuple(indicators),
            ioc_source=source,
        )
