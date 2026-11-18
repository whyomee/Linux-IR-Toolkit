"""User account and privilege investigation.

Reads account databases, sudoers rules, group membership and login history.
Password hashes are never stored or reported: /etc/shadow is only classified
as empty, locked or hash-present.
"""

from __future__ import annotations

import os
import re
import time
from datetime import timedelta
from pathlib import Path
from typing import Any

import psutil

from irkit.accountparse import (
    Account,
    SUDO_GROUPS,
    parse_group,
    parse_passwd,
    parse_shadow_status,
    parse_sudoers,
)
from irkit.collectors.base import BaseCollector
from irkit.models import Confidence
from irkit.utils import iso_utc, utc_now

_LAST_LINE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<start>[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+"
    r"(?P<end>.+)$"
)
_INTERACTIVE_SHELLS = {"/bin/sh", "/bin/bash", "/bin/dash", "/bin/zsh", "/bin/ksh", "/bin/fish", "/usr/bin/sh", "/usr/bin/bash"}


class UserCollector(BaseCollector):
    name = "users"
    description = "Accounts, UID 0 aliases, sudo privileges and login history"
    requires_root = False

    def run(self) -> None:
        passwd_text = self.read_text(self.ctx.paths.passwd, "Local account database", required=True)
        if passwd_text is None:
            self.note_warning("cannot read /etc/passwd; account analysis is unavailable")
            return
        accounts = parse_passwd(passwd_text)
        by_name = {account.name: account for account in accounts}

        group_text = self.read_text(self.ctx.paths.group, "Local group database", required=False)
        groups = parse_group(group_text) if group_text else {}

        shadow_statuses = self._shadow_statuses()
        sudoers = self._sudoers_entries()

        uid0 = [account for account in accounts if account.uid == 0]
        duplicates = self._duplicate_uids(accounts)
        recent = self._recent_accounts(accounts)
        system_shells = [
            account
            for account in accounts
            if 0 < account.uid < 1000 and account.shell in _INTERACTIVE_SHELLS
        ]

        self.data.update(
            {
                "accounts": [account.to_dict() for account in accounts],
                "account_count": len(accounts),
                "uid0_accounts": [account.name for account in uid0],
                "duplicate_uids": duplicates,
                "shadow": shadow_statuses,
                "sudo_groups": self._sudo_group_data(groups),
                "sudoers": sudoers,
                "current_sessions": self._current_sessions(),
                "login_history": self._login_history(),
                "recent_accounts": recent,
                "system_accounts_with_interactive_shell": [account.name for account in system_shells],
                "passwd_metadata": self._metadata(self.ctx.paths.passwd),
            }
        )

        self._account_findings(accounts, uid0, duplicates, shadow_statuses, recent, system_shells, sudoers)

    # -- data helpers ------------------------------------------------------
    def _metadata(self, path: Path) -> dict[str, Any]:
        try:
            info = path.stat()
        except OSError as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}
        return {"mtime": iso_utc(info.st_mtime), "size": info.st_size, "mode": oct(info.st_mode & 0o777)}

    def _shadow_statuses(self) -> dict[str, Any]:
        # Never digest or retain shadow content: only the classification below is kept.
        text = self.read_text(
            self.ctx.paths.shadow,
            "Password shadow database",
            required=False,
            hash_content=False,
        )
        if text is None:
            if not self.is_root:
                self.note_warning(
                    "cannot read /etc/shadow without root; empty-password and lock state could not be verified"
                )
            else:
                self.note_warning("cannot read /etc/shadow; empty-password checks were skipped")
            return {"readable": False, "status_counts": {}, "empty_password_accounts": [], "locked_accounts": []}
        statuses = parse_shadow_status(text)
        counts: dict[str, int] = {}
        for status in statuses.values():
            counts[status.status] = counts.get(status.status, 0) + 1
        return {
            "readable": True,
            "status_counts": counts,
            "empty_password_accounts": sorted(name for name, item in statuses.items() if item.status == "empty"),
            "locked_accounts": sorted(name for name, item in statuses.items() if item.status in {"locked", "no_password"}),
            "entries": {name: status.to_dict() for name, status in statuses.items()},
        }

    def _sudoers_entries(self) -> dict[str, Any]:
        files: list[Path] = []
        if self.ctx.paths.sudoers.exists():
            files.append(self.ctx.paths.sudoers)
        if self.ctx.paths.sudoers_d.is_dir():
            try:
                files.extend(
                    sorted(
                        entry
                        for entry in self.ctx.paths.sudoers_d.iterdir()
                        if entry.is_file() and "." not in entry.name and not entry.name.endswith("~")
                    )
                )
            except OSError as exc:
                self.note_warning(f"cannot list /etc/sudoers.d: {exc}")
        entries: list[dict[str, Any]] = []
        for path in files:
            text = self.read_text(path, f"Sudoers policy ({path.name})")
            if not text:
                continue
            for entry in parse_sudoers(text, self.rel(path)):
                entries.append(entry.to_dict())
        nopasswd = [entry for entry in entries if entry["nopasswd"]]
        return {
            "files": [self.rel(path) for path in files],
            "entries": entries[:200],
            "entry_count": len(entries),
            "nopasswd_entries": nopasswd,
        }

    @staticmethod
    def _duplicate_uids(accounts: list[Account]) -> dict[str, list[str]]:
        by_uid: dict[int, list[str]] = {}
        for account in accounts:
            if account.uid == 65534:  # nobody/nogroup commonly share this UID
                continue
            if account.uid == 0:
                # Shared UID 0 is already covered by USER_UID0_NONROOT; reporting
                # it again as a duplicate would double-count the same evidence.
                continue
            by_uid.setdefault(account.uid, []).append(account.name)
        return {str(uid): names for uid, names in by_uid.items() if len(names) > 1}

    @staticmethod
    def _sudo_group_data(groups: dict[str, Any]) -> list[dict[str, Any]]:
        return [
            {"name": group.name, "gid": group.gid, "members": group.members}
            for name, group in sorted(groups.items())
            if name in SUDO_GROUPS
        ]

    def _current_sessions(self) -> list[dict[str, Any]]:
        sessions: list[dict[str, Any]] = []
        try:
            for user in psutil.users():
                sessions.append(
                    {
                        "user": user.name,
                        "terminal": user.terminal,
                        "host": user.host,
                        "started": iso_utc(user.started),
                        "pid": user.pid,
                    }
                )
        except (psutil.Error, OSError) as exc:
            self.note_warning(f"cannot enumerate current sessions: {exc}")
        return sessions

    def _login_history(self) -> dict[str, Any]:
        result = self.command(["last", "-F", "-w", "-n", "50"], "Recent login history (wtmp)")
        if not result.ok:
            return {"available": False, "error": result.error or result.stderr.strip()[:300], "entries": [], "raw": []}
        entries: list[dict[str, Any]] = []
        for line in result.stdout.splitlines():
            match = _LAST_LINE.match(line.strip())
            if match:
                entries.append(match.groupdict())
        return {
            "available": True,
            "entries": entries[:50],
            "raw": [line for line in result.stdout.splitlines() if line.strip()][:50],
        }

    def _recent_accounts(self, accounts: list[Account]) -> list[dict[str, Any]]:
        """Compare against /etc/passwd- to identify added accounts.

        The backup file is maintained by shadow-utils on Debian/Ubuntu and most
        RPM distributions.  When it is absent, no claim is made about account
        age beyond home-directory ctime, which is reported separately as weak.
        """
        backup_text = self.read_text(self.ctx.paths.passwd_backup, "Previous account database", required=False)
        if backup_text is None:
            self.note_warning("/etc/passwd- is unavailable; newly added accounts cannot be diffed reliably")
            return []
        previous = {account.name for account in parse_passwd(backup_text)}
        current = {account.name for account in accounts}
        added = sorted(current - previous)
        removed = sorted(previous - current)
        recent: list[dict[str, Any]] = []
        threshold = utc_now() - timedelta(days=self.ctx.config.thresholds.recent_account_days)
        for name in added:
            account = next(item for item in accounts if item.name == name)
            recent.append({**account.to_dict(), "reason": "present in /etc/passwd but absent from /etc/passwd-"})
        for account in accounts:
            home = self._home_path(account)
            if home is None or not home.is_dir():
                continue
            try:
                created = home.stat().st_ctime
            except OSError:
                continue
            if created >= threshold.timestamp():
                recent.append(
                    {
                        **account.to_dict(),
                        "reason": "home directory ctime is recent",
                        "home_ctime": iso_utc(created),
                    }
                )
        self.data["removed_accounts"] = removed
        return recent

    def _home_path(self, account: Account) -> Path | None:
        """Return an account's home only when it is under the real /home tree.

        Service accounts often use paths such as /usr/sbin or /var/lib as their
        "home".  Those directories change constantly and would produce a stream
        of meaningless "recent home" findings, so they are deliberately ignored.
        """
        if not account.home.startswith("/"):
            return None
        candidate = self.ctx.paths.root / account.home.lstrip("/")
        try:
            if not candidate.is_relative_to(self.ctx.paths.home):
                return None
        except (OSError, ValueError):
            return None
        return candidate

    # -- detections --------------------------------------------------------
    def _account_findings(
        self,
        accounts: list[Account],
        uid0: list[Account],
        duplicates: dict[str, list[str]],
        shadow: dict[str, Any],
        recent: list[dict[str, Any]],
        system_shells: list[Account],
        sudoers: dict[str, Any],
    ) -> None:
        passwd_evidence = [item for item in self.evidence if item.source_path and item.source_path.endswith("/passwd")]
        shadow_evidence = [item for item in self.evidence if item.source_path and item.source_path.endswith("/shadow")]
        backup_evidence = [item for item in self.evidence if item.source_path and item.source_path.endswith("passwd-")]

        for account in uid0:
            if account.name == "root":
                continue
            self.add_finding(
                "USER_UID0_NONROOT",
                f"Account {account.name!r} has UID 0 (shell {account.shell}, home {account.home}).",
                details=account.to_dict(),
                evidence=passwd_evidence,
                confidence=Confidence.HIGH,
            )

        for uid, names in duplicates.items():
            self.add_finding(
                "USER_DUPLICATE_UID",
                f"UID {uid} is shared by accounts: {', '.join(names)}.",
                details={"uid": int(uid), "accounts": names},
                evidence=passwd_evidence,
                confidence=Confidence.HIGH,
            )

        for name in shadow.get("empty_password_accounts", []):
            self.add_finding(
                "USER_EMPTY_PASSWORD",
                f"Account {name!r} has an empty password field in /etc/shadow.",
                details={"account": name},
                evidence=shadow_evidence,
                confidence=Confidence.HIGH,
            )

        for entry in sudoers.get("nopasswd_entries", []):
            principal = str(entry.get("principal", "")).strip()
            if principal == "root":
                continue
            self.add_finding(
                "USER_SUDO_NOPASSWD",
                f"Sudoers rule for {principal!r} grants passwordless execution: {entry.get('spec')} "
                f"({entry.get('source')}:{entry.get('line_number')}).",
                details=entry,
                evidence=[item for item in self.evidence if item.source_path and "sudoers" in item.source_path],
                confidence=Confidence.MEDIUM,
            )

        for group in self.data.get("sudo_groups", []):
            members = [member for member in group.get("members", []) if member != "root"]
            if not members:
                continue
            self.add_finding(
                "USER_SUDO_GROUP_MEMBER",
                f"Group {group['name']!r} (GID {group['gid']}) grants sudo capability to: {', '.join(members)}.",
                details={"group": group["name"], "gid": group["gid"], "members": members},
                evidence=[item for item in self.evidence if item.source_path and item.source_path.endswith("/group")],
                confidence=Confidence.HIGH,
            )

        for account in system_shells:
            self.add_finding(
                "USER_SYSTEM_ACCOUNT_INTERACTIVE",
                f"System account {account.name!r} (UID {account.uid}) has interactive shell {account.shell}.",
                details=account.to_dict(),
                evidence=passwd_evidence,
                confidence=Confidence.MEDIUM,
            )

        for entry in recent:
            name = entry.get("name", "unknown")
            uid = entry.get("uid")
            reason = str(entry.get("reason") or "")
            if uid == 0 and "absent from /etc/passwd-" in reason:
                self.add_finding(
                    "USER_RECENT_UID0_ACCOUNT",
                    f"Root-equivalent account {name!r} is present in /etc/passwd but absent "
                    f"from /etc/passwd-.",
                    details=entry,
                    evidence=passwd_evidence + backup_evidence,
                    confidence=Confidence.MEDIUM,
                )
            elif uid == 0:
                # A recent ctime on root's home is not evidence that the account
                # itself was created recently; avoid a misleading critical finding.
                continue
            elif "home directory ctime" in reason:
                self.add_finding(
                    "USER_HOME_RECENT",
                    f"Home directory for {name!r} has a recent creation/change time: {entry.get('home_ctime')}.",
                    details=entry,
                    evidence=passwd_evidence,
                    confidence=Confidence.LOW,
                )
            else:
                self.add_finding(
                    "USER_RECENT_ACCOUNT",
                    f"Account {name!r} (UID {uid}) is present in /etc/passwd but absent from /etc/passwd-.",
                    details=entry,
                    evidence=passwd_evidence + backup_evidence,
                    confidence=Confidence.MEDIUM,
                )
