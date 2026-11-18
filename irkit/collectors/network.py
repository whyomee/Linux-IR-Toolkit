"""Network investigation collector.

Parses ``/proc/net/{tcp,tcp6,udp,udp6}`` directly (works without root) and maps
socket inodes to owning processes through ``/proc/<pid>/fd``.  No packets are
captured and no connections are made.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import time
from pathlib import Path
from typing import Any

import psutil

from irkit.collectors.base import BaseCollector
from irkit.models import Confidence, Severity
from irkit.utils import iso_utc, split_proc_address, truncate

_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
    "0C": "NEW_SYN_RECV",
}

_NET_FILES = (
    ("tcp", socket.AF_INET, "tcp"),
    ("tcp6", socket.AF_INET6, "tcp"),
    ("udp", socket.AF_INET, "udp"),
    ("udp6", socket.AF_INET6, "udp"),
)

_WILDCARD = {"0.0.0.0", "::"}


def _is_public_address(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_unspecified)


def _port_name(port: int, proto: str) -> str | None:
    try:
        return socket.getservbyport(port, proto)
    except OSError:
        return None


class NetworkCollector(BaseCollector):
    name = "network"
    description = "Listening ports, established connections and owning processes"
    requires_root = False

    def run(self) -> None:
        owners = self._socket_owners()
        listeners: list[dict[str, Any]] = []
        established: list[dict[str, Any]] = []
        udp_sockets: list[dict[str, Any]] = []
        unattributed_listeners: list[dict[str, Any]] = []
        parse_errors = 0
        files_read = 0

        for filename, family, proto in _NET_FILES:
            path = self.ctx.paths.proc / "net" / filename
            if not path.exists():
                continue
            text = self.read_text(path, f"/proc/net/{filename} socket table")
            if text is None:
                continue
            files_read += 1
            for line in text.splitlines()[1:]:
                fields = line.split()
                if len(fields) < 10:
                    continue
                try:
                    local_ip, local_port = split_proc_address(fields[1], family)
                    remote_ip, remote_port = split_proc_address(fields[2], family)
                except (ValueError, OSError):
                    parse_errors += 1
                    continue
                state_code = fields[3].upper()
                state = _STATES.get(state_code, state_code)
                inode = fields[9]
                uid = int(fields[7]) if fields[7].isdigit() else None
                owner = owners.get(inode, {})
                pid = owner.get("pid")
                exe = owner.get("exe")
                process_name = owner.get("name")
                username = owner.get("username")
                deleted = bool(exe and exe.endswith(" (deleted)"))
                suspicious = self._is_suspicious_exe(exe) or deleted

                record: dict[str, Any] = {
                    "proto": proto,
                    "family": "IPv6" if family == socket.AF_INET6 else "IPv4",
                    "local_address": local_ip,
                    "local_port": local_port,
                    "port_name": _port_name(local_port, proto),
                    "uid": uid,
                    "inode": inode,
                    "pid": pid,
                    "process": process_name,
                    "username": username,
                    "exe": exe,
                    "deleted_executable": deleted,
                }

                if proto == "tcp" and state == "LISTEN":
                    record["wildcard"] = local_ip in _WILDCARD
                    record["public_exposure"] = record["wildcard"] or _is_public_address(local_ip)
                    listeners.append(record)
                    if pid is None:
                        unattributed_listeners.append(record)
                    if suspicious:
                        self._suspicious_finding("NET_SUSPICIOUS_LISTENER", record)
                elif proto == "tcp" and state == "ESTABLISHED":
                    record.update(
                        {
                            "remote_address": remote_ip,
                            "remote_port": remote_port,
                            "remote_port_name": _port_name(remote_port, proto),
                            "state": state,
                            "remote_is_public": _is_public_address(remote_ip),
                        }
                    )
                    established.append(record)
                    if suspicious:
                        self._suspicious_finding("NET_SUSPICIOUS_CONNECTION", record)
                elif proto == "udp":
                    record.update(
                        {
                            "remote_address": remote_ip,
                            "remote_port": remote_port,
                            "state": state,
                        }
                    )
                    udp_sockets.append(record)

        listeners.sort(key=lambda item: (item["local_port"], item["proto"]))
        established.sort(key=lambda item: (item.get("remote_address") or "", item["local_port"]))
        udp_sockets.sort(key=lambda item: item["local_port"])

        public_listeners = [item for item in listeners if item.get("public_exposure")]
        remote_endpoints: dict[tuple[str, int], int] = {}
        for item in established:
            key = (str(item.get("remote_address")), int(item.get("remote_port") or 0))
            remote_endpoints[key] = remote_endpoints.get(key, 0) + 1

        self.data.update(
            {
                "listeners": listeners,
                "established": established,
                "udp_sockets": udp_sockets[:500],
                "summary": {
                    "listeners": len(listeners),
                    "established": len(established),
                    "udp_sockets": len(udp_sockets),
                    "public_listeners": len(public_listeners),
                    "unattributed_listeners": len(unattributed_listeners),
                    "unique_remote_endpoints": len(remote_endpoints),
                    "parse_errors": parse_errors,
                    "files_read": files_read,
                },
                "public_listener_ports": sorted({int(item["local_port"]) for item in public_listeners}),
                "remote_endpoints": [
                    {"address": address, "port": port, "count": count}
                    for (address, port), count in sorted(remote_endpoints.items(), key=lambda item: item[1], reverse=True)[:50]
                ],
                "collected_at": iso_utc(),
            }
        )

        if files_read == 0:
            self.note_warning("no /proc/net socket tables were readable; network inventory is empty")
        if parse_errors:
            self.note_warning(f"{parse_errors} socket table line(s) could not be parsed")
        if not self.is_root:
            self.note_warning(
                "socket-to-process attribution is limited without root; some sockets will show no owning process"
            )

        if public_listeners:
            self.add_finding(
                "NET_PUBLIC_LISTENER",
                f"{len(public_listeners)} listening socket(s) accept connections on all interfaces "
                f"(ports: {', '.join(str(port) for port in self.data['public_listener_ports'][:30])}).",
                details={
                    "count": len(public_listeners),
                    "ports": self.data["public_listener_ports"],
                    "listeners": [
                        {
                            "proto": item["proto"],
                            "local_address": item["local_address"],
                            "local_port": item["local_port"],
                            "process": item["process"],
                            "pid": item["pid"],
                        }
                        for item in public_listeners[:50]
                    ],
                },
                confidence=Confidence.HIGH,
            )

        if self.is_root and unattributed_listeners:
            self.add_finding(
                "NET_UNATTRIBUTED_LISTENER",
                f"{len(unattributed_listeners)} listening socket(s) could not be attributed to a process.",
                details={
                    "count": len(unattributed_listeners),
                    "sockets": [
                        {
                            "proto": item["proto"],
                            "local_address": item["local_address"],
                            "local_port": item["local_port"],
                            "inode": item["inode"],
                            "uid": item["uid"],
                        }
                        for item in unattributed_listeners[:50]
                    ],
                },
                confidence=Confidence.LOW,
            )

    # -- helpers -----------------------------------------------------------
    def _is_suspicious_exe(self, exe: str | None) -> bool:
        if not exe:
            return False
        candidate = Path(exe)
        paths = self.ctx.paths
        for root in (paths.tmp, paths.var_tmp, paths.dev_shm, paths.run_shm, paths.home):
            try:
                if candidate.resolve(strict=False).is_relative_to(root.resolve(strict=False)):
                    return True
            except (OSError, ValueError):
                continue
        return False

    def _suspicious_finding(self, rule_id: str, record: dict[str, Any]) -> None:
        pid = record.get("pid")
        evidence = []
        if pid is not None:
            evidence.append(
                self.evidence_file(
                    self.ctx.paths.proc / str(pid) / "exe",
                    f"Executable image for PID {pid} ({record.get('process')}) associated with a network socket",
                )
            )
        # A loopback-only socket cannot be reached from the network, so the
        # exposure is materially lower than a public listener or connection.
        # Severity is reduced rather than suppressing the observation.
        severity = None
        if rule_id == "NET_SUSPICIOUS_LISTENER" and not record.get("public_exposure"):
            severity = Severity.MEDIUM
        elif rule_id == "NET_SUSPICIOUS_CONNECTION" and not record.get("remote_is_public"):
            severity = Severity.MEDIUM
        self.add_finding(
            rule_id,
            (
                f"{record['proto'].upper()} socket on {record['local_address']}:{record['local_port']} "
                f"is owned by PID {pid} ({record.get('process')!r}) executing {record.get('exe')!r}"
                + (" from a deleted file" if record.get("deleted_executable") else "")
            ),
            details=record,
            evidence=[item for item in evidence if item],
            confidence=Confidence.MEDIUM,
            severity=severity,
        )

    def _socket_owners(self) -> dict[str, dict[str, Any]]:
        """Map socket inodes to owning processes via /proc/<pid>/fd."""
        owners: dict[str, dict[str, Any]] = {}
        proc_dir = self.ctx.paths.proc
        if not proc_dir.is_dir():
            return owners
        deadline = time.monotonic() + 20.0
        try:
            pids = [entry.name for entry in os.scandir(proc_dir) if entry.name.isdigit()]
        except OSError as exc:
            self.note_warning(f"cannot enumerate /proc for socket owners: {exc}")
            return owners

        for pid_text in pids:
            if time.monotonic() > deadline:
                self.note_warning("socket owner scan hit its time budget; attribution may be incomplete")
                break
            fd_dir = proc_dir / pid_text / "fd"
            try:
                descriptors = list(os.scandir(fd_dir))
            except OSError:
                continue
            pid = int(pid_text)
            details: dict[str, Any] | None = None
            for descriptor in descriptors:
                try:
                    target = os.readlink(descriptor.path)
                except OSError:
                    continue
                if not target.startswith("socket:["):
                    continue
                inode = target[8:-1]
                if details is None:
                    details = self._process_details(pid)
                owners[inode] = {"pid": pid, **details}
        return owners

    def _process_details(self, pid: int) -> dict[str, Any]:
        details: dict[str, Any] = {"name": None, "exe": None, "username": None}
        try:
            process = psutil.Process(pid)
            details["name"] = process.name()
            details["username"] = process.username()
            exe = process.exe()
            details["exe"] = exe
        except (psutil.Error, OSError):
            pass
        if details["name"] is None:
            comm = self.read_text(
                self.ctx.paths.proc / str(pid) / "comm",
                None,
                required=False,
                record=False,
            )
            if comm:
                details["name"] = comm.strip()
        if details["exe"] is None:
            try:
                details["exe"] = os.readlink(self.ctx.paths.proc / str(pid) / "exe")
            except OSError:
                pass
        if details["exe"]:
            details["exe"] = truncate(details["exe"], 4096)
        return details
