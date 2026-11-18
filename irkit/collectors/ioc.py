"""IOC correlation collector.

Searches collected evidence for analyst-supplied IPs, domains, URLs, file
hashes and paths.  Matching is exact for hashes and IPs, and boundary-aware for
domains, URLs, paths and strings.  All correlation is local; no lookup or
upload occurs.
"""

from __future__ import annotations

import ipaddress
import os
import re
from typing import Any, Iterable

from irkit.collectors.base import BaseCollector
from irkit.models import Confidence, Severity
from irkit.utils import truncate

_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6 = re.compile(r"(?<![\w:])(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}(?![\w:])")
_MAX_TEXTS = 20_000
_MAX_MATCHES = 1_000
_MAX_LOCATIONS_PER_INDICATOR = 25


class IOCCollector(BaseCollector):
    name = "ioc"
    description = "Correlate supplied indicators against collected evidence"
    requires_root = False

    def run(self) -> None:
        indicators = self._indicators()
        if not indicators:
            self.mark_skipped("no IOC indicators supplied")
            self.data.update(
                {
                    "source": self.ctx.config.ioc_source,
                    "indicators": [],
                    "matches": [],
                    "match_count": 0,
                    "note": "No indicators were supplied. Use --ioc-file to enable correlation.",
                }
            )
            return

        index = self._build_index()
        self.data["index_size"] = {
            "texts": len(index["texts"]),
            "ips": len(index["ips"]),
            "hashes": len(index["hashes"]),
            "paths": len(index["paths"]),
        }

        all_matches: list[dict[str, Any]] = []
        matched_indicators = 0
        for indicator in indicators:
            matches = self._match(indicator, index)
            if not matches:
                continue
            matched_indicators += 1
            matches = matches[:_MAX_LOCATIONS_PER_INDICATOR]
            all_matches.extend(matches)
            if len(all_matches) >= _MAX_MATCHES:
                self.note_warning(f"IOC match limit reached ({_MAX_MATCHES}); additional matches were not recorded")
                break
            rule_id = "IOC_MATCH_HASH" if indicator["type"] in {"sha256", "sha1", "md5"} else "IOC_MATCH"
            evidence_refs = sorted({match["evidence_id"] for match in matches if match.get("evidence_id")})
            self.add_finding(
                rule_id,
                f"{indicator['type']} indicator {indicator['value']} matched {len(matches)} collected "
                f"location(s): "
                + "; ".join(f"{match['collector']}.{match['field']}" for match in matches[:5]),
                details={
                    "indicator": indicator,
                    "match_count": len(matches),
                    "matches": matches,
                },
                evidence=evidence_refs,
                severity=indicator["severity"],
                confidence=Confidence.HIGH if indicator["type"] in {"sha256", "sha1", "md5"} else Confidence.MEDIUM,
                title=f"IOC match: {indicator['type']} {indicator['value']}",
            )

        self.data.update(
            {
                "source": self.ctx.config.ioc_source,
                "indicators": indicators,
                "indicator_count": len(indicators),
                "matches": all_matches[:_MAX_MATCHES],
                "match_count": len(all_matches),
                "matched_indicator_count": matched_indicators,
                "searched_collectors": sorted(index["collectors"]),
                "note": "Matches are correlations with supplied indicators, not proof of compromise.",
            }
        )
        self.evidence_data(
            "ioc-analysis",
            {"indicators": indicators, "matches": all_matches[:200]},
            "IOC indicator list and correlation results",
        )
        if not all_matches:
            self.note_warning("none of the supplied indicators matched collected evidence")

    # -- input -------------------------------------------------------------
    def _indicators(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for raw in self.ctx.config.ioc_indicators:
            if not isinstance(raw, dict):
                continue
            value = str(raw.get("value") or "").strip()
            kind = str(raw.get("type") or "").strip().lower()
            if not value or not kind:
                continue
            try:
                severity = Severity.from_str(str(raw.get("severity") or "high"))
            except ValueError:
                severity = Severity.HIGH
            result.append(
                {
                    "type": kind,
                    "value": value,
                    "severity": severity,
                    "description": str(raw.get("description") or "analyst-supplied indicator"),
                    "source": raw.get("source"),
                }
            )
        return result

    # -- index -------------------------------------------------------------
    def _build_index(self) -> dict[str, Any]:
        texts: list[dict[str, Any]] = []
        ips: list[dict[str, Any]] = []
        hashes: dict[str, list[dict[str, Any]]] = {}
        paths: dict[str, list[dict[str, Any]]] = {}
        collectors: set[str] = set()

        def add_text(collector: str, field: str, value: Any, evidence_id: str | None = None) -> None:
            if not isinstance(value, str) or not value.strip():
                return
            if len(texts) >= _MAX_TEXTS:
                return
            collectors.add(collector)
            texts.append(
                {
                    "collector": collector,
                    "field": field,
                    "text": value,
                    "evidence_id": evidence_id,
                }
            )
            for match in _IPV4.findall(value):
                add_ip(collector, field, match, value, evidence_id)
            for match in _IPV6.findall(value):
                add_ip(collector, field, match, value, evidence_id)

        def add_ip(
            collector: str,
            field: str,
            value: Any,
            context: str | None = None,
            evidence_id: str | None = None,
        ) -> None:
            if not isinstance(value, str) or not value:
                return
            try:
                normalised = ipaddress.ip_address(value.split("%", 1)[0]).compressed
            except ValueError:
                return
            collectors.add(collector)
            ips.append(
                {
                    "ip": normalised,
                    "collector": collector,
                    "field": field,
                    "context": truncate(context or value, 300),
                    "evidence_id": evidence_id,
                }
            )

        def add_path(
            collector: str,
            field: str,
            value: Any,
            context: str | None = None,
            evidence_id: str | None = None,
        ) -> None:
            if not isinstance(value, str) or not value.startswith("/"):
                return
            normalised = os.path.normpath(value)
            collectors.add(collector)
            location = {
                "collector": collector,
                "field": field,
                "context": truncate(context or value, 300),
                "evidence_id": evidence_id,
            }
            paths.setdefault(normalised, []).append(location)
            add_text(collector, field, value, evidence_id)

        # Evidence manifest: hashes and source paths are authoritative.
        for item in self.ctx.evidence.items:
            collectors.add("evidence")
            if item.sha256:
                hashes.setdefault(item.sha256, []).append(
                    {
                        "collector": "evidence",
                        "field": "sha256",
                        "context": item.source_path or item.command or item.description,
                        "evidence_id": item.evidence_id,
                    }
                )
            if item.source_path:
                add_path("evidence", "source_path", item.source_path, item.description, item.evidence_id)
            if item.command:
                add_text("evidence", "command", item.command, item.evidence_id)

        # Network
        network = self.ctx.prior_data("network")
        for record in list(network.get("listeners", [])) + list(network.get("established", [])):
            add_ip("network", "local_address", record.get("local_address"), record.get("process"))
            add_ip("network", "remote_address", record.get("remote_address"), record.get("process"))
            add_text("network", "process", record.get("process"))
            add_text("network", "exe", record.get("exe"))
            add_path("network", "exe", record.get("exe"))
        for endpoint in network.get("remote_endpoints", []):
            add_ip("network", "remote_endpoint", endpoint.get("address"), f"count={endpoint.get('count')}")

        # Processes
        processes = self.ctx.prior_data("processes")
        for record in processes.get("processes", []):
            add_text("processes", "cmdline", record.get("cmdline_str"))
            add_text("processes", "name", record.get("name"))
            add_text("processes", "exe", record.get("exe"))
            add_text("processes", "cwd", record.get("cwd"))
            add_path("processes", "exe", record.get("exe"))
            add_path("processes", "cwd", record.get("cwd"))

        # Users
        users = self.ctx.prior_data("users")
        for account in users.get("accounts", []):
            for field in ("name", "home", "shell", "gecos"):
                add_text("users", field, account.get(field))
            add_path("users", "home", account.get("home"))
        for entry in users.get("sudoers", {}).get("entries", []):
            add_text("users", "sudoers_principal", entry.get("principal"))
            add_text("users", "sudoers_spec", entry.get("spec"))
        for session in users.get("current_sessions", []):
            add_ip("users", "session_host", session.get("host"), session.get("user"))
            add_text("users", "session_host", session.get("host"))
        for line in users.get("login_history", {}).get("raw", []):
            add_text("users", "login_history", line)

        # SSH
        ssh = self.ctx.prior_data("ssh")
        for values in ssh.get("config", {}).get("values", {}).values():
            for value in values:
                add_text("ssh", "sshd_config", value)
        for entry in ssh.get("authorized_keys", {}).get("files", []):
            add_path("ssh", "authorized_keys", entry.get("absolute_path"), entry.get("account"))
            add_text("ssh", "authorized_keys_path", entry.get("path"))
            for key in entry.get("keys", []):
                add_text("ssh", "key_comment", key.get("comment"))
                add_text("ssh", "key_options", key.get("options"))
                add_text("ssh", "key_fingerprint", key.get("fingerprint"))
        for private in ssh.get("private_keys", []):
            add_text("ssh", "private_key_path", private.get("path"))
        auth = ssh.get("authentication", {})
        for ip in list(auth.get("failed_by_ip", {})) + list(auth.get("accepted_by_ip", {})):
            add_ip("ssh", "authentication_source", ip)
        for session in auth.get("root_accepts", []):
            add_ip("ssh", "root_login_source", session.get("source_ip"))

        # Persistence
        persistence = self.ctx.prior_data("persistence")
        for entry in persistence.get("cron", {}).get("entries", []):
            add_text("persistence", "cron_command", entry.get("command"))
            add_text("persistence", "cron_source", entry.get("source"))
            add_path("persistence", "cron_source", entry.get("source"))
        for unit in persistence.get("systemd", {}).get("units", []):
            add_path("persistence", "systemd_unit", unit.get("path"))
            for exec_item in unit.get("exec", []):
                add_text("persistence", "systemd_exec", exec_item.get("command"))
        for record in persistence.get("systemd", {}).get("user_units", []):
            for unit in record.get("units", []):
                add_path("persistence", "user_systemd_unit", unit.get("path"))
                for exec_item in unit.get("exec", []):
                    add_text("persistence", "user_systemd_exec", exec_item.get("command"))
        for entry in persistence.get("linker", {}).get("preload", {}).get("entries", []):
            add_path("persistence", "ld_preload", entry)
        for record in persistence.get("startup", {}).get("profiles", []):
            add_path("persistence", "profile", record.get("path"))
        for record in persistence.get("startup", {}).get("sshrc", []):
            add_path("persistence", "sshrc", record.get("path"))
        for job in persistence.get("at_jobs", {}).get("jobs", []):
            add_path("persistence", "at_job", job.get("path"))
        for script in persistence.get("initd", {}).get("scripts", []):
            add_path("persistence", "init_script", script.get("path"))

        # Filesystem
        filesystem = self.ctx.prior_data("filesystem")
        for record in filesystem.get("sensitive_files", []):
            add_path("filesystem", "sensitive_file", record.get("absolute_path"), record.get("mode"))
        for record in filesystem.get("suid", {}).get("files", []):
            add_path("filesystem", "suid_file", record.get("absolute_path"), record.get("mode"))
        for record in filesystem.get("temporary_directories", {}).get("files", []):
            add_path("filesystem", "temporary_file", record.get("absolute_path"), record.get("mtime"))
        for record in filesystem.get("world_writable", {}).get("directories", []):
            add_path("filesystem", "world_writable_dir", record.get("path"))

        # Logs
        logs = self.ctx.prior_data("logs")
        for event in logs.get("auth", {}).get("events", []):
            add_ip("logs", "auth_source", event.get("source_ip"), event.get("message"))
            add_text("logs", "auth_message", event.get("message"))
            add_text("logs", "auth_method", event.get("method"))
            add_text("logs", "auth_user", event.get("user"))
        for record in logs.get("syslog", {}).get("recent_errors", []):
            add_text("logs", "syslog_error", record.get("message"))
        for record in logs.get("auth", {}).get("summary", {}).get("account_events", []):
            add_text("logs", "account_event", record.get("message"))

        # System
        system = self.ctx.prior_data("system")
        for value in system.get("os_release", {}).values():
            add_text("system", "os_release", value)
        add_text("system", "kernel_cmdline", system.get("kernel", {}).get("cmdline"))
        add_text("system", "hostname", system.get("hostname"))
        for mount in system.get("mounts", []):
            add_text("system", "mount_device", mount.get("device"))
            add_path("system", "mountpoint", mount.get("mountpoint"))

        return {"texts": texts, "ips": ips, "hashes": hashes, "paths": paths, "collectors": collectors}

    # -- matching ----------------------------------------------------------
    def _match(self, indicator: dict[str, Any], index: dict[str, Any]) -> list[dict[str, Any]]:
        kind = indicator["type"]
        value = indicator["value"]
        matches: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str]] = set()

        def add(location: dict[str, Any]) -> None:
            key = (
                str(location.get("collector")),
                str(location.get("field")),
                str(location.get("context"))[:200],
            )
            if key in seen:
                return
            seen.add(key)
            matches.append(
                {
                    "indicator": value,
                    "type": kind,
                    "severity": indicator["severity"].value,
                    "collector": location.get("collector"),
                    "field": location.get("field"),
                    "context": truncate(str(location.get("context") or ""), 300),
                    "evidence_id": location.get("evidence_id"),
                }
            )

        if kind in {"sha256", "sha1", "md5"}:
            for location in index["hashes"].get(value, []):
                add(location)
            return matches

        if kind == "ip":
            for location in index["ips"]:
                if location["ip"] == value:
                    add(location)
            return matches

        if kind == "path":
            normalised = os.path.normpath(value)
            for location in index["paths"].get(normalised, []):
                add(location)
            token = re.compile(r"(?<![\w./-])" + re.escape(value) + r"(?![\w./-])")
            for entry in index["texts"]:
                if token.search(entry["text"]):
                    add(entry)
            return matches

        if kind == "domain":
            pattern = re.compile(r"(?<![A-Za-z0-9-])" + re.escape(value) + r"(?![A-Za-z0-9-])", re.IGNORECASE)
            for entry in index["texts"]:
                if pattern.search(entry["text"]):
                    add(entry)
            return matches

        # URL and generic string matching.
        needle = value.lower()
        for entry in index["texts"]:
            if needle in entry["text"].lower():
                add(entry)
        return matches
