"""System information collector.

Collects host identity, OS/kernel details, uptime, mounts and security
posture.  Purely informational data is separated from findings so the report
can show context without inflating risk.
"""

from __future__ import annotations

import os
import platform
import socket
import time
from pathlib import Path
from typing import Any

import psutil

from irkit.collectors.base import BaseCollector
from irkit.config import VIRTUAL_FILESYSTEMS
from irkit.utils import human_bytes, human_duration, iso_utc, utc_now

_TAINT_BITS = {
    0: "proprietary module loaded",
    1: "module force-loaded",
    2: "kernel forced to use workaround",
    3: "machine check exception",
    4: "bad page detected",
    5: "user-requested taint",
    6: "kernel oops/die occurred",
    7: "ACPI table overridden",
    8: "kernel warning issued",
    9: "staging driver loaded",
    10: "workaround for kernel bug",
    11: "out-of-tree module loaded",
    12: "unsigned module loaded",
    13: "soft lockup occurred",
    14: "live patch applied",
    15: "auxiliary taint",
    16: "struct page taint",
}

_SAFE_INITS = {"/sbin/init", "/lib/systemd/systemd", "/usr/lib/systemd/systemd"}


def _parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key.strip()] = value
    return values


class SystemCollector(BaseCollector):
    name = "system"
    description = "Host identity, OS, kernel, uptime, mounts and security posture"
    requires_root = False

    def run(self) -> None:
        self.data.update(
            {
                "hostname": self._safe(lambda: socket.gethostname()),
                "fqdn": self._safe(lambda: socket.getfqdn()),
                "os_release": self._os_release(),
                "platform": platform.platform(),
                "architecture": platform.machine(),
                "kernel": self._kernel(),
                "uptime": self._uptime(),
                "cpu": self._cpu(),
                "memory": self._memory(),
                "swap": self._swap(),
                "virtualization": self._virtualization(),
                "systemd": self._systemd(),
                "security": self._security(),
                "mounts": self._mounts(),
                "time": {
                    "collected_at": iso_utc(),
                    "timezone": time.tzname[0] if time.tzname else None,
                    "utc_offset_seconds": -time.timezone,
                },
                "reboot_required": self._reboot_required(),
                "collection": {"euid": os.geteuid(), "is_root": self.is_root},
            }
        )
        self._hostname_finding()
        self._cmdline_finding()

    # -- data helpers ------------------------------------------------------
    @staticmethod
    def _safe(callable_: Any, default: Any = None) -> Any:
        try:
            return callable_()
        except Exception:  # noqa: BLE001 - platform variance is expected
            return default

    def _os_release(self) -> dict[str, str]:
        text = self.read_text(self.ctx.paths.os_release, "Operating system identification")
        if text is None:
            self.note_warning("cannot read /etc/os-release; OS identification is limited")
            return {}
        return _parse_os_release(text)

    def _kernel(self) -> dict[str, Any]:
        version_text = self.read_text(self.ctx.paths.proc_version, "Running kernel version")
        cmdline = self.read_text(self.ctx.paths.proc_cmdline, "Kernel command line")
        return {
            "release": platform.release(),
            "version_string": version_text.strip() if version_text else None,
            "cmdline": cmdline.strip() if cmdline else None,
            "architecture": platform.machine(),
        }

    def _uptime(self) -> dict[str, Any]:
        boot = self._safe(psutil.boot_time)
        if not boot:
            self.note_warning("cannot determine boot time")
            return {"boot_time": None, "uptime_seconds": None, "uptime_human": "unknown"}
        seconds = max(0.0, utc_now().timestamp() - float(boot))
        return {
            "boot_time": iso_utc(float(boot)),
            "uptime_seconds": int(seconds),
            "uptime_human": human_duration(seconds),
        }

    def _cpu(self) -> dict[str, Any]:
        return {
            "logical": self._safe(psutil.cpu_count, None),
            "physical": self._safe(lambda: psutil.cpu_count(logical=False), None),
        }

    def _memory(self) -> dict[str, Any]:
        memory = self._safe(psutil.virtual_memory)
        if memory is None:
            self.note_warning("cannot read memory information")
            return {}
        return {
            "total": memory.total,
            "available": memory.available,
            "used": memory.used,
            "percent": memory.percent,
            "total_human": human_bytes(memory.total),
        }

    def _swap(self) -> dict[str, Any]:
        swap = self._safe(psutil.swap_memory)
        if swap is None:
            return {}
        return {"total": swap.total, "used": swap.used, "percent": swap.percent}

    def _virtualization(self) -> dict[str, Any]:
        result = self.command(
            ["systemd-detect-virt"],
            "Virtualization detection",
            record=True,
        )
        container_marker = self.ctx.paths.p("run", "systemd", "container")
        container = None
        if container_marker.exists():
            container = self._safe(lambda: container_marker.read_text(encoding="utf-8", errors="replace").strip())
        return {
            "detected": result.stdout.strip() if result.ok and result.stdout.strip() else None,
            "container_marker": container,
        }

    def _systemd(self) -> dict[str, Any]:
        present = self.ctx.paths.p("run", "systemd", "system").exists()
        version_result = self.command(["systemctl", "--version"], "systemd version") if present else None
        version = None
        if version_result is not None and version_result.ok and version_result.stdout:
            first_line = version_result.stdout.splitlines()[0]
            version = first_line.strip()
        state = None
        if present:
            state_result = self.command(["systemctl", "is-system-running"], "systemd overall state")
            if state_result.stdout.strip():
                state = state_result.stdout.strip().splitlines()[0]
        return {"present": present, "version": version, "state": state}

    def _security(self) -> dict[str, Any]:
        taint_text = self.read_text(self.ctx.paths.kernel_taint, "Kernel taint flags")
        taint: int | None = None
        taint_bits: list[str] = []
        if taint_text is not None:
            try:
                taint = int(taint_text.strip())
                taint_bits = [description for bit, description in _TAINT_BITS.items() if taint & (1 << bit)]
            except ValueError:
                self.note_warning("cannot parse kernel taint value")

        lsm_text = self.read_text(
            self.ctx.paths.p("sys", "kernel", "security", "lsm"),
            "Active Linux Security Modules",
            required=False,
        )
        apparmor_text = self.read_text(self.ctx.paths.apparmor_profiles, "AppArmor profiles", required=False)
        selinux_text = self.read_text(self.ctx.paths.selinux_enforce, "SELinux enforcement mode", required=False)

        apparmor_count = None
        if apparmor_text is not None:
            apparmor_count = sum(1 for line in apparmor_text.splitlines() if line.strip() and not line.startswith("name"))

        selinux_mode = None
        if selinux_text is not None:
            selinux_mode = {"0": "permissive", "1": "enforcing"}.get(selinux_text.strip(), selinux_text.strip())

        if taint:
            self.add_finding(
                "SYS_KERNEL_TAINTED",
                f"The running kernel has taint value {taint} ({'; '.join(taint_bits) or 'unknown bits'}).",
                details={"taint": taint, "bits": taint_bits},
                evidence=[
                    item
                    for item in self.evidence
                    if item.source_path and item.source_path.endswith("tainted")
                ],
            )
        return {
            "kernel_tainted": taint,
            "kernel_taint_bits": taint_bits,
            "lsm": [value.strip() for value in lsm_text.split(",")] if lsm_text else [],
            "apparmor_profile_lines": apparmor_count,
            "selinux_mode": selinux_mode,
        }

    def _mounts(self) -> list[dict[str, Any]]:
        mounts: list[dict[str, Any]] = []
        partitions = self._safe(lambda: psutil.disk_partitions(all=False), []) or []
        for partition in partitions:
            entry: dict[str, Any] = {
                "device": partition.device,
                "mountpoint": partition.mountpoint,
                "fstype": partition.fstype,
                "options": partition.opts,
                "virtual": partition.fstype in VIRTUAL_FILESYSTEMS,
            }
            usage = self._safe(lambda mp=partition.mountpoint: psutil.disk_usage(mp))
            if usage is not None:
                entry.update(
                    {
                        "total": usage.total,
                        "used": usage.used,
                        "free": usage.free,
                        "percent": usage.percent,
                    }
                )
            mounts.append(entry)
        if not mounts:
            self.note_warning("no mounted filesystems could be enumerated")
        return mounts

    def _reboot_required(self) -> bool:
        return self.ctx.paths.p("run", "reboot-required").exists() or self.ctx.paths.p(
            "var", "run", "reboot-required"
        ).exists()

    # -- detections --------------------------------------------------------
    def _hostname_finding(self) -> None:
        runtime = self.data.get("hostname")
        text = self.read_text(self.ctx.paths.hostname_file, "Static hostname", required=False)
        if not text or not runtime:
            return
        static = text.strip().splitlines()[0].strip() if text.strip() else ""
        if static and static != runtime:
            self.add_finding(
                "SYS_HOSTNAME_MISMATCH",
                f"Runtime hostname {runtime!r} differs from /etc/hostname value {static!r}.",
                details={"runtime": runtime, "static": static},
                evidence=[item for item in self.evidence if item.source_path and item.source_path.endswith("/hostname")],
            )

    def _cmdline_finding(self) -> None:
        cmdline = (self.data.get("kernel") or {}).get("cmdline") or ""
        tokens = cmdline.split()
        suspicious: list[str] = []
        for token in tokens:
            if token.startswith("init="):
                init_path = token.split("=", 1)[1]
                if init_path not in _SAFE_INITS:
                    suspicious.append(token)
            elif token in {"single", "1", "s", "S", "rd.break"} or token.startswith("rd.break="):
                suspicious.append(token)
            elif token.startswith("systemd.unit=") and any(
                target in token for target in ("rescue.target", "emergency.target", "single.target")
            ):
                suspicious.append(token)
        if suspicious:
            self.add_finding(
                "SYS_SUSPICIOUS_KERNEL_CMDLINE",
                "Kernel command line contains rescue or single-user boot parameters: " + ", ".join(suspicious),
                details={"cmdline": cmdline, "matched": suspicious},
                evidence=[item for item in self.evidence if item.source_path and item.source_path.endswith("cmdline")],
            )
