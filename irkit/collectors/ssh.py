"""SSH investigation collector.

Audits effective sshd configuration, authorized_keys files and authentication
logs.  Private keys are never read: only their metadata and permissions are
examined.  Authentication analysis uses the same parser as the log collector.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from irkit.accountparse import (
    looks_like_private_key,
    parse_authorized_key,
    parse_passwd,
)
from irkit.collectors.base import BaseCollector
from irkit.logparse import AuthEvent, parse_auth_events, read_log, summarise_auth_events
from irkit.models import Confidence
from irkit.patterns import match_patterns
from irkit.utils import iso_utc, utc_now

_DEFAULTS = {
    "permitrootlogin": "prohibit-password",
    "passwordauthentication": "yes",
    "permitemptypasswords": "no",
    "pubkeyauthentication": "yes",
    "maxauthtries": "6",
}


class SSHCollector(BaseCollector):
    name = "ssh"
    description = "sshd configuration, authorized keys and authentication activity"
    requires_root = False

    def run(self) -> None:
        config = self._read_config()
        self.data["config"] = config
        self._config_findings(config)

        keys = self._authorized_keys(config)
        self.data["authorized_keys"] = keys
        self._key_findings(keys)

        private = self._private_key_metadata()
        self.data["private_keys"] = private
        self._private_key_findings(private)

        auth = self._auth_analysis()
        self.data["authentication"] = auth
        self._auth_findings(auth)

    # -- sshd configuration ------------------------------------------------
    def _read_config(self) -> dict[str, Any]:
        files: list[Path] = []
        if self.ctx.paths.sshd_config.exists():
            files.append(self.ctx.paths.sshd_config)
        if self.ctx.paths.sshd_config_d.is_dir():
            try:
                files.extend(sorted(self.ctx.paths.sshd_config_d.glob("*.conf")))
            except OSError as exc:
                self.note_warning(f"cannot list sshd_config.d: {exc}")

        effective: dict[str, str] = {}
        values: dict[str, list[str]] = {}
        match_blocks: list[dict[str, Any]] = []
        seen: set[Path] = set()
        include_errors: list[str] = []

        def process(path: Path, depth: int) -> None:
            if depth > 3 or path in seen:
                return
            seen.add(path)
            text = self.read_text(path, f"SSH daemon configuration ({path.name})", required=False)
            if text is None:
                return
            in_match = False
            current_match: dict[str, Any] | None = None
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                key = parts[0].lower()
                value = parts[1].strip() if len(parts) > 1 else ""
                if key == "match":
                    in_match = True
                    current_match = {"condition": value, "settings": {}}
                    match_blocks.append(current_match)
                    continue
                if key == "include":
                    in_match = False
                    for token in value.split():
                        pattern = Path(token)
                        if pattern.is_absolute():
                            try:
                                pattern = pattern.resolve(strict=False)
                            except OSError:
                                continue
                            if not pattern.is_relative_to(self.ctx.paths.root.resolve(strict=False)):
                                include_errors.append(f"include outside collection root ignored: {token}")
                                continue
                        else:
                            pattern = self.ctx.paths.ssh_dir / pattern
                        for included in sorted(pattern.parent.glob(pattern.name)):
                            if included.is_file():
                                process(included, depth + 1)
                    continue
                if in_match and current_match is not None:
                    current_match["settings"][key] = value
                    continue
                effective[key] = value
                values.setdefault(key, []).append(value)

        for path in files:
            process(path, 0)

        available = bool(files)
        if not available:
            self.note_warning("no sshd configuration found; SSH server may not be installed")
        merged = {key: effective.get(key, default) for key, default in _DEFAULTS.items()}
        merged.update({key: value for key, value in effective.items() if key not in merged})
        return {
            "available": available,
            "files": [self.rel(path) for path in sorted(seen)],
            "effective": merged,
            "explicit": effective,
            "values": values,
            "match_blocks": match_blocks,
            "include_errors": include_errors,
        }

    def _config_findings(self, config: dict[str, Any]) -> None:
        if not config.get("available"):
            return
        effective = config["effective"]
        evidence = [item for item in self.evidence if item.source_path and "/ssh/" in item.source_path]

        def value(key: str) -> str:
            return str(effective.get(key, "")).strip().lower()

        if value("permitemptypasswords") == "yes":
            self.add_finding(
                "SSH_PERMIT_EMPTY_PASSWORDS",
                "Effective sshd configuration has PermitEmptyPasswords yes.",
                details={"setting": "PermitEmptyPasswords", "value": "yes", "files": config["files"]},
                evidence=evidence,
                confidence=Confidence.HIGH,
            )
        if value("permitrootlogin") == "yes":
            self.add_finding(
                "SSH_ROOT_LOGIN_ENABLED",
                "Effective sshd configuration has PermitRootLogin yes.",
                details={"setting": "PermitRootLogin", "value": "yes", "files": config["files"]},
                evidence=evidence,
                confidence=Confidence.HIGH,
            )
        if value("passwordauthentication") == "yes":
            self.add_finding(
                "SSH_PASSWORD_AUTH_ENABLED",
                "Effective sshd configuration has PasswordAuthentication yes.",
                details={"setting": "PasswordAuthentication", "value": "yes", "files": config["files"]},
                evidence=evidence,
                confidence=Confidence.HIGH,
            )
        try:
            max_tries = int(value("maxauthtries"))
        except ValueError:
            max_tries = None
        if max_tries is not None and max_tries > 6:
            self.add_finding(
                "SSH_WEAK_MAX_AUTH_TRIES",
                f"Effective sshd MaxAuthTries is {max_tries}, above the hardening baseline of 6.",
                details={"setting": "MaxAuthTries", "value": max_tries, "files": config["files"]},
                evidence=evidence,
                confidence=Confidence.HIGH,
            )

    # -- authorized keys ---------------------------------------------------
    def _accounts(self) -> list[dict[str, Any]]:
        text = self.read_text(self.ctx.paths.passwd, "Account database (for SSH key discovery)", required=False)
        accounts: list[dict[str, Any]] = []
        if text:
            for account in parse_passwd(text):
                accounts.append({"name": account.name, "home": account.home, "uid": account.uid})
        if not any(item["name"] == "root" for item in accounts):
            accounts.append({"name": "root", "home": "/root", "uid": 0})
        return accounts

    def _authorized_keys(self, config: dict[str, Any]) -> dict[str, Any]:
        accounts = self._accounts()
        key_files = config.get("values", {}).get("authorizedkeysfile", [".ssh/authorized_keys .ssh/authorized_keys2"])
        patterns: list[str] = []
        for value in key_files:
            for token in value.split():
                if token.lower() == "none":
                    continue
                patterns.append(token)
        if not patterns:
            patterns = [".ssh/authorized_keys"]

        candidates: list[tuple[str, Path]] = []
        seen: set[Path] = set()
        for account in accounts:
            home_value = str(account.get("home") or "")
            if not home_value.startswith("/"):
                continue
            home = self.ctx.paths.root / home_value.lstrip("/")
            for pattern in patterns:
                expanded = pattern.replace("%h", str(home)).replace("%u", str(account["name"]))
                candidate = Path(expanded)
                if not candidate.is_absolute():
                    candidate = home / candidate
                if candidate in seen or not candidate.exists():
                    continue
                seen.add(candidate)
                candidates.append((str(account["name"]), candidate))

        # Also discover homes that are not represented in /etc/passwd.
        if self.ctx.paths.home.is_dir():
            try:
                for entry in sorted(self.ctx.paths.home.iterdir()):
                    if not entry.is_dir() or entry.is_symlink():
                        continue
                    for pattern in patterns:
                        candidate = Path(pattern.replace("%h", str(entry)).replace("%u", entry.name))
                        if not candidate.is_absolute():
                            candidate = entry / candidate
                        if candidate.exists() and candidate not in seen:
                            seen.add(candidate)
                            candidates.append((entry.name, candidate))
            except OSError as exc:
                self.note_warning(f"cannot enumerate home directories: {exc}")

        entries: list[dict[str, Any]] = []
        for account_name, path in candidates[: self.ctx.limits.max_authorized_key_files]:
            metadata = self._safe_stat(path)
            text = self.read_text(path, f"SSH authorized keys for {account_name}")
            evidence = [item for item in self.evidence if item.source_path and str(path) == item.source_path]
            keys = []
            if text:
                for line in text.splitlines():
                    parsed = parse_authorized_key(line)
                    if parsed is not None:
                        keys.append(parsed.to_dict())
            entries.append(
                {
                    "account": account_name,
                    "path": self.rel(path),
                    "absolute_path": str(path),
                    "mtime": iso_utc(metadata.get("mtime")) if metadata.get("mtime") else None,
                    "mode": metadata.get("mode"),
                    "mode_octal": metadata.get("mode_octal"),
                    "world_writable": metadata.get("world_writable", False),
                    "group_writable": metadata.get("group_writable", False),
                    "keys": keys,
                    "key_count": len(keys),
                    "readable": text is not None,
                    "evidence_id": evidence[0].evidence_id if evidence else None,
                }
            )
        return {"files": entries, "count": len(entries), "patterns": patterns}

    def _safe_stat(self, path: Path) -> dict[str, Any]:
        try:
            info = path.stat()
        except OSError:
            return {}
        return {
            "mtime": info.st_mtime,
            "mode": stat.filemode(info.st_mode),
            "mode_octal": oct(stat.S_IMODE(info.st_mode)),
            "world_writable": bool(info.st_mode & stat.S_IWOTH),
            "group_writable": bool(info.st_mode & stat.S_IWGRP),
        }

    def _key_findings(self, keys: dict[str, Any]) -> None:
        threshold = utc_now() - timedelta(days=self.ctx.config.thresholds.authorized_key_recent_days)
        for entry in keys.get("files", []):
            evidence = [entry["evidence_id"]] if entry.get("evidence_id") else []
            if entry.get("world_writable"):
                self.add_finding(
                    "SSH_AUTHORIZED_KEY_WORLD_WRITABLE",
                    f"{entry['path']} (account {entry['account']}) is world-writable ({entry.get('mode_octal')}).",
                    details=entry,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                )
            if entry.get("mtime") and entry.get("readable"):
                try:
                    mtime = datetime.fromisoformat(str(entry["mtime"]).replace("Z", "+00:00"))
                except ValueError:
                    mtime = None
                if mtime is not None and mtime >= threshold:
                    self.add_finding(
                        "SSH_AUTHORIZED_KEY_RECENT",
                        f"{entry['path']} (account {entry['account']}, {entry['key_count']} key(s)) "
                        f"was modified at {entry['mtime']}.",
                        details={key: entry[key] for key in ("account", "path", "mtime", "key_count", "keys")},
                        evidence=evidence,
                        confidence=Confidence.MEDIUM,
                    )
            if entry["account"] == "root" and entry["key_count"] > 0:
                self.add_finding(
                    "SSH_AUTHORIZED_KEY_ROOT",
                    f"Root account has {entry['key_count']} authorized SSH key(s) in {entry['path']}.",
                    details={"path": entry["path"], "keys": entry["keys"]},
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                )
            for key in entry.get("keys", []):
                patterns = match_patterns(str(key.get("options", "")))
                if patterns:
                    self.add_finding(
                        "SSH_AUTHORIZED_KEY_FORCED_COMMAND",
                        f"Key {key['fingerprint']} for {entry['account']} has options matching: "
                        + ", ".join(item["name"] for item in patterns),
                        details={"path": entry["path"], "key": key, "patterns": patterns},
                        evidence=evidence,
                        confidence=Confidence.MEDIUM,
                    )

    # -- private key metadata ---------------------------------------------
    def _private_key_metadata(self) -> list[dict[str, Any]]:
        candidates: list[tuple[str, Path]] = []
        for account in self._accounts():
            home_value = str(account.get("home") or "")
            if not home_value.startswith("/"):
                continue
            ssh_dir = self.ctx.paths.root / home_value.lstrip("/") / ".ssh"
            if not ssh_dir.is_dir():
                continue
            try:
                for entry in ssh_dir.iterdir():
                    if entry.is_file() and not entry.is_symlink() and looks_like_private_key(entry.name):
                        candidates.append((str(account["name"]), entry))
            except OSError:
                continue
        if self.ctx.paths.ssh_dir.is_dir():
            try:
                for entry in self.ctx.paths.ssh_dir.iterdir():
                    if entry.is_file() and entry.name.startswith("ssh_host_") and entry.name.endswith("_key"):
                        candidates.append(("sshd-host-key", entry))
            except OSError:
                pass

        results: list[dict[str, Any]] = []
        for account_name, path in candidates[:100]:
            metadata = self._safe_stat(path)
            if not metadata:
                continue
            mode = int(str(metadata["mode_octal"]), 8) if metadata.get("mode_octal") else 0
            exposed = bool(mode & (stat.S_IRGRP | stat.S_IROTH))
            self.evidence_file(path, f"SSH private key metadata for {account_name}", hash_content=False)
            results.append(
                {
                    "account": account_name,
                    "path": self.rel(path),
                    "absolute_path": str(path),
                    "mode": metadata.get("mode"),
                    "mode_octal": metadata.get("mode_octal"),
                    "group_or_world_readable": exposed,
                }
            )
        return results

    def _private_key_findings(self, private: list[dict[str, Any]]) -> None:
        for entry in private:
            if entry.get("group_or_world_readable"):
                absolute = entry.get("absolute_path")
                evidence = [
                    item
                    for item in self.evidence
                    if item.source_path and (item.source_path == absolute or item.source_path == entry["path"])
                ]
                self.add_finding(
                    "SSH_PRIVATE_KEY_EXPOSED",
                    f"Private key {entry['path']} for {entry['account']} is readable by group or other "
                    f"users ({entry.get('mode_octal')}).",
                    details=entry,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                )

    # -- authentication activity ------------------------------------------
    def _auth_analysis(self) -> dict[str, Any]:
        patterns = ["auth.log", "auth.log.*", "secure", "secure.*"]
        files = self.ctx.paths.log_candidates(patterns)
        files = sorted(files, key=lambda path: self._mtime(path), reverse=True)[: self.ctx.limits.max_log_files]
        sources: list[dict[str, Any]] = []
        events: list[AuthEvent] = []
        journal: dict[str, Any] = {"used": False}

        if files:
            per_file_lines = max(1000, self.ctx.limits.max_log_lines // max(1, len(files)))
            for path in files:
                log = read_log(path, per_file_lines, self.ctx.limits.max_read_bytes * 4)
                self.evidence_file(path, f"SSH authentication log ({path.name})")
                parsed = parse_auth_events(log.lines, self.rel(path))
                events.extend(parsed)
                sources.append(
                    {
                        "path": self.rel(path),
                        "lines_read": len(log.lines),
                        "events_parsed": len(parsed),
                        "truncated": log.truncated,
                        "error": log.error,
                    }
                )
                if log.error:
                    self.note_warning(f"cannot read {self.rel(path)}: {log.error}")
        else:
            result = self.command(
                ["journalctl", "--no-pager", "-o", "short-iso", "-n", "5000"],
                "Journal excerpt for SSH authentication analysis",
            )
            journal = {"used": True, "ok": result.ok, "error": result.error, "lines": len(result.stdout.splitlines())}
            if result.ok and result.stdout:
                parsed = parse_auth_events(result.stdout.splitlines(), "journalctl")
                events.extend(parsed)
                sources.append({"path": "journalctl", "lines_read": len(result.stdout.splitlines()), "events_parsed": len(parsed)})
            if not result.ok:
                self.note_warning("no SSH auth logs found and journalctl was unavailable")

        if not sources:
            self.note_warning("no SSH authentication logs were available; login activity was not analysed")

        summary = summarise_auth_events(events)
        failed_by_ip: dict[str, int] = {}
        failed_users: dict[str, set[str]] = {}
        accepted_by_ip: dict[str, int] = {}
        accepted_users: dict[str, set[str]] = {}
        root_accepts: list[dict[str, Any]] = []
        for event in events:
            if event.kind == "ssh_failed" and event.source_ip:
                failed_by_ip[event.source_ip] = failed_by_ip.get(event.source_ip, 0) + 1
                if event.user:
                    failed_users.setdefault(event.source_ip, set()).add(event.user)
            elif event.kind == "ssh_accepted" and event.source_ip:
                accepted_by_ip[event.source_ip] = accepted_by_ip.get(event.source_ip, 0) + 1
                if event.user:
                    accepted_users.setdefault(event.source_ip, set()).add(event.user)
                    if event.user == "root":
                        root_accepts.append(
                            {"timestamp": event.timestamp, "source_ip": event.source_ip, "source": event.source}
                        )
        return {
            "available": bool(sources),
            "sources": sources,
            "journal": journal,
            "summary": summary,
            "failed_by_ip": failed_by_ip,
            "failed_users_by_ip": {key: sorted(value) for key, value in failed_users.items()},
            "accepted_by_ip": accepted_by_ip,
            "accepted_users_by_ip": {key: sorted(value) for key, value in accepted_users.items()},
            "root_accepts": root_accepts[:20],
        }

    @staticmethod
    def _mtime(path: Path) -> float:
        try:
            return path.stat().st_mtime
        except OSError:
            return 0.0

    def _auth_findings(self, auth: dict[str, Any]) -> None:
        if not auth.get("available"):
            return
        thresholds = self.ctx.config.thresholds
        evidence = [item for item in self.evidence if item.source_path and ("auth.log" in item.source_path or "secure" in item.source_path)]
        failures: dict[str, int] = auth.get("failed_by_ip", {})
        accepted: dict[str, int] = auth.get("accepted_by_ip", {})

        for ip, count in sorted(failures.items(), key=lambda item: item[1], reverse=True):
            if count < thresholds.ssh_failures_per_ip:
                continue
            self.add_finding(
                "SSH_FAILED_LOGIN_BURST",
                f"{count} failed SSH authentication attempts from {ip} (targeted accounts: "
                f"{', '.join(auth['failed_users_by_ip'].get(ip, [])) or 'unknown'}).",
                details={
                    "source_ip": ip,
                    "failures": count,
                    "targeted_users": auth["failed_users_by_ip"].get(ip, []),
                    "successes_from_source": accepted.get(ip, 0),
                },
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        total_failures = sum(failures.values())
        if total_failures >= thresholds.ssh_failures_total and all(
            count < thresholds.ssh_failures_per_ip for count in failures.values()
        ):
            self.add_finding(
                "SSH_FAILED_LOGIN_BURST",
                f"{total_failures} failed SSH authentication attempts were recorded across "
                f"{len(failures)} source addresses.",
                details={"total_failures": total_failures, "sources": len(failures)},
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        for ip, success_count in accepted.items():
            failed_count = failures.get(ip, 0)
            if failed_count < thresholds.ssh_success_after_failures:
                continue
            self.add_finding(
                "SSH_SUCCESS_AFTER_FAILURES",
                f"{success_count} successful SSH login(s) from {ip} after {failed_count} failures "
                f"(accounts: {', '.join(auth['accepted_users_by_ip'].get(ip, []))}).",
                details={
                    "source_ip": ip,
                    "failures": failed_count,
                    "successes": success_count,
                    "accounts": auth["accepted_users_by_ip"].get(ip, []),
                },
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )

        root_accepts = auth.get("root_accepts", [])
        if root_accepts:
            self.add_finding(
                "SSH_ROOT_LOGIN_SUCCESS",
                f"{len(root_accepts)} successful SSH login(s) as root were recorded "
                f"(sources: {', '.join(sorted({str(item['source_ip']) for item in root_accepts}))}).",
                details={"count": len(root_accepts), "sessions": root_accepts},
                evidence=evidence,
                confidence=Confidence.MEDIUM,
            )
