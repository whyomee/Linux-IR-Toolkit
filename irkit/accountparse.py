"""Parsers for account databases, sudoers, SSH keys and systemd units.

These parsers are pure functions over text so they can be tested directly and
reused by several collectors without coupling them together.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

_SSH_KEY_TYPES = re.compile(
    r"^(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-[A-Za-z0-9.-]+|sk-(?:ssh-ed25519|ecdsa-sha2-[A-Za-z0-9.-]+)@openssh\.com)$"
)
_AUTHORIZED_KEY = re.compile(
    r"^(?:(?P<options>(?:\S+,)*\S+)\s+)?(?P<type>ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-\S+|sk-\S+)\s+"
    r"(?P<blob>[A-Za-z0-9+/=]+)(?:\s+(?P<comment>.*))?$"
)
_SSH_PRIVATE_HEADER = re.compile(r"-----BEGIN (?:OPENSSH|RSA|DSA|EC|PRIVATE) PRIVATE KEY-----")

SAFE_SHELLS = frozenset({"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""})
SUDO_GROUPS = frozenset({"sudo", "wheel", "admin", "doas"})


@dataclass
class Account:
    name: str
    uid: int
    gid: int
    gecos: str
    home: str
    shell: str
    password_marker: str  # x | * | ! | empty | hash | other

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "uid": self.uid,
            "gid": self.gid,
            "gecos": self.gecos,
            "home": self.home,
            "shell": self.shell,
            "password_marker": self.password_marker,
        }


@dataclass
class Group:
    name: str
    gid: int
    members: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"name": self.name, "gid": self.gid, "members": list(self.members)}


@dataclass
class ShadowStatus:
    name: str
    status: str  # empty | locked | no_password | hash | unknown
    last_change_days: int | None = None
    max_days: int | None = None
    inactive_days: int | None = None
    expire_days: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "status": self.status,
            "last_change_days": self.last_change_days,
            "max_days": self.max_days,
            "inactive_days": self.inactive_days,
            "expire_days": self.expire_days,
        }


@dataclass
class SudoersEntry:
    source: str
    line_number: int
    principal: str
    spec: str
    nopasswd: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "line_number": self.line_number,
            "principal": self.principal,
            "spec": self.spec,
            "nopasswd": self.nopasswd,
        }


@dataclass
class AuthorizedKey:
    key_type: str
    fingerprint: str
    comment: str
    options: str

    def to_dict(self) -> dict[str, object]:
        return {
            "key_type": self.key_type,
            "fingerprint": self.fingerprint,
            "comment": self.comment,
            "options": self.options,
        }


def _marker_kind(marker: str) -> str:
    if marker == "":
        return "empty"
    if marker == "x":
        return "x"
    if marker in {"*", "!"}:
        return "no_password"
    if marker.startswith("!") or marker.startswith("*"):
        return "locked"
    if marker.startswith("$") or len(marker) > 20:
        return "hash"
    return "other"


def parse_passwd(text: str) -> list[Account]:
    """Parse ``/etc/passwd`` without retaining password field content."""
    accounts: list[Account] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        name, marker, uid_raw, gid_raw, gecos, home, shell = parts[:7]
        try:
            uid = int(uid_raw)
            gid = int(gid_raw)
        except ValueError:
            continue
        accounts.append(
            Account(
                name=name,
                uid=uid,
                gid=gid,
                gecos=gecos,
                home=home,
                shell=shell,
                password_marker=_marker_kind(marker),
            )
        )
    return accounts


def parse_group(text: str) -> dict[str, Group]:
    """Parse ``/etc/group`` into a name-keyed mapping."""
    groups: dict[str, Group] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 4:
            continue
        name, _, gid_raw, members_raw = parts[:4]
        try:
            gid = int(gid_raw)
        except ValueError:
            continue
        members = [member for member in members_raw.split(",") if member]
        groups[name] = Group(name=name, gid=gid, members=members)
    return groups


def parse_shadow_status(text: str) -> dict[str, ShadowStatus]:
    """Summarise ``/etc/shadow`` without retaining password hashes.

    The hash field is classified (empty, locked, hash present) and then
    discarded.  Only aging metadata is kept for reporting.
    """
    statuses: dict[str, ShadowStatus] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        name, hash_field = parts[0], parts[1]
        if hash_field == "":
            status = "empty"
        elif hash_field.startswith("!") or hash_field.startswith("*"):
            status = "locked"
        elif hash_field in {"x", "!!"}:
            status = "no_password"
        else:
            status = "hash"

        def number(index: int) -> int | None:
            if index >= len(parts) or parts[index] == "":
                return None
            try:
                return int(parts[index])
            except ValueError:
                return None

        statuses[name] = ShadowStatus(
            name=name,
            status=status,
            last_change_days=number(2),
            max_days=number(4),
            inactive_days=number(6),
            expire_days=number(7),
        )
    return statuses


def parse_sudoers(text: str, source: str) -> list[SudoersEntry]:
    """Extract sudoers rules, flagging NOPASSWD grants.

    ``#include``/``@include`` directives are ignored here; the caller reads
    ``/etc/sudoers.d`` separately, which is where includes normally point.
    """
    entries: list[SudoersEntry] = []
    for index, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("@"):
            continue
        if line.lower().startswith(("defaults", "include", "includedir", "cmnd_alias", "user_alias", "runas_alias", "host_alias")):
            continue
        if "=" not in line:
            continue
        # A rule is ``principal host = (runas) command``.  Splitting on ``=``
        # leaves the host part attached to the principal, so take only the first
        # token as the principal and keep the remainder as the specification.
        match = re.match(r"^(?P<principal>\S+)\s+\S+\s*=\s*(?P<spec>.*)$", line)
        if match:
            principal = match.group("principal")
            spec = match.group("spec")
        else:
            principal, spec = line.split("=", 1)
        principal = principal.strip()
        if not principal:
            continue
        entries.append(
            SudoersEntry(
                source=source,
                line_number=index,
                principal=principal,
                spec=spec.strip(),
                nopasswd="NOPASSWD" in spec.upper(),
            )
        )
    return entries


def ssh_key_fingerprint(blob_b64: str) -> str | None:
    """Compute the OpenSSH-style SHA-256 fingerprint of a public key blob."""
    try:
        raw = base64.b64decode(blob_b64, validate=True)
    except (binascii.Error, ValueError):
        return None
    digest = hashlib.sha256(raw).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def parse_authorized_key(line: str) -> AuthorizedKey | None:
    """Parse an authorized_keys line, returning metadata only.

    The base64 key blob is converted to a fingerprint and discarded; only the
    public-key fingerprint, type, comment and options are retained.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    match = _AUTHORIZED_KEY.match(stripped)
    if not match:
        return None
    fingerprint = ssh_key_fingerprint(match.group("blob"))
    if fingerprint is None:
        return None
    return AuthorizedKey(
        key_type=match.group("type"),
        fingerprint=fingerprint,
        comment=(match.group("comment") or "").strip(),
        options=(match.group("options") or "").strip(),
    )


def looks_like_private_key(path_name: str) -> bool:
    """Heuristic for identifying private-key filenames without reading them."""
    name = path_name.rsplit("/", 1)[-1]
    return name in {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} or name.startswith("id_") and not name.endswith(".pub")


def contains_private_key_header(text: str) -> bool:
    """Detect a private-key header in already-read text (used for sshrc etc.)."""
    return bool(_SSH_PRIVATE_HEADER.search(text))


def parse_unit(text: str) -> dict[str, dict[str, list[str]]]:
    """Parse a systemd unit file into ``section -> key -> values``.

    Duplicate keys are preserved because systemd allows repeated ExecStart=
    lines.  Continuation lines ending in a backslash are joined.
    """
    sections: dict[str, dict[str, list[str]]] = {}
    current: str | None = None
    buffer = ""
    for raw in text.splitlines():
        line = raw.rstrip()
        if not buffer and (not line.strip() or line.lstrip().startswith(("#", ";"))):
            continue
        if line.endswith("\\"):
            buffer += line[:-1].rstrip() + " "
            continue
        line = buffer + line.strip()
        buffer = ""
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if current is None or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        sections[current].setdefault(key, []).append(value)
    return sections


def unit_exec_lines(sections: dict[str, dict[str, list[str]]]) -> list[tuple[str, str]]:
    """Return ``(key, command)`` pairs for all execution directives."""
    service = sections.get("Service", {})
    result: list[tuple[str, str]] = []
    for key in ("ExecStartPre", "ExecStart", "ExecReload", "ExecStop", "ExecStopPost"):
        for value in service.get(key, []):
            result.append((key, value))
    return result
