"""Tests for the pure account, sudoers, SSH key and systemd parsers."""

from __future__ import annotations

import base64

from irkit.accountparse import (
    contains_private_key_header,
    looks_like_private_key,
    parse_authorized_key,
    parse_group,
    parse_passwd,
    parse_shadow_status,
    parse_sudoers,
    parse_unit,
    ssh_key_fingerprint,
    unit_exec_lines,
)

PASSWD = """# comment
root:x:0:0:root:/root:/bin/bash
alice:x:1000:1000:Alice:/home/alice:/bin/bash
broken:x:notanumber:1000:bad:/home/broken:/bin/sh
short:x:1:1
"""

SHADOW = """root:!:19000:0:99999:7:::
alice::19000:0:99999:7:::
bob:$6$salt$hash:19000:0:99999:7:::
carol:!!:19000:0:99999:7:::
"""


def test_parse_passwd_keeps_only_safe_fields() -> None:
    accounts = parse_passwd(PASSWD)
    assert [account.name for account in accounts] == ["root", "alice"]
    assert accounts[0].uid == 0
    assert accounts[1].home == "/home/alice"
    assert accounts[1].password_marker == "x"


def test_parse_passwd_classifies_password_markers() -> None:
    accounts = parse_passwd("a::0:0::/root:/bin/sh\nb:*:1:1::/:/bin/sh\nc:!:2:2::/:/bin/sh\n")
    assert [account.password_marker for account in accounts] == ["empty", "no_password", "no_password"]


def test_parse_group_and_members() -> None:
    groups = parse_group("sudo:x:27:alice,bob\nwheel:x:10:\ninvalid:x:notnum:\n")
    assert groups["sudo"].members == ["alice", "bob"]
    assert groups["wheel"].members == []
    assert "invalid" not in groups


def test_parse_shadow_discards_hashes() -> None:
    statuses = parse_shadow_status(SHADOW)
    assert statuses["alice"].status == "empty"
    assert statuses["root"].status == "locked"
    assert statuses["bob"].status == "hash"
    assert statuses["carol"].status == "locked"
    assert statuses["bob"].max_days == 99999
    serialised = {name: item.to_dict() for name, item in statuses.items()}
    assert "hash" in str(serialised["bob"]["status"])
    assert "$6$salt$hash" not in str(serialised)


def test_parse_sudoers_flags_nopasswd() -> None:
    text = """# comment
Defaults env_reset
alice ALL=(ALL:ALL) NOPASSWD: ALL
bob ALL=(ALL) /usr/bin/systemctl restart nginx
"""
    entries = parse_sudoers(text, "/etc/sudoers")
    assert len(entries) == 2
    assert entries[0].principal == "alice"
    assert entries[0].nopasswd is True
    assert entries[1].nopasswd is False
    assert entries[1].line_number == 4


def test_authorized_key_fingerprint_is_stable_and_content_free() -> None:
    blob = base64.b64encode(b"deterministic key blob").decode()
    line = f'ssh-ed25519 {blob} alice@example'
    key = parse_authorized_key(line)
    assert key is not None
    assert key.key_type == "ssh-ed25519"
    assert key.fingerprint == ssh_key_fingerprint(blob)
    assert key.fingerprint.startswith("SHA256:")
    assert key.comment == "alice@example"
    assert blob not in key.to_dict().values()


def test_authorized_key_with_options_and_invalid_blob() -> None:
    blob = base64.b64encode(b"another blob").decode()
    key = parse_authorized_key(f'command="/bin/true",no-pty ssh-rsa {blob} ops')
    assert key is not None
    assert "command=" in key.options
    assert parse_authorized_key("ssh-rsa !!!not-base64!!! bad") is None


def test_private_key_helpers_do_not_read_content() -> None:
    assert looks_like_private_key("id_rsa") is True
    assert looks_like_private_key("id_ed25519") is True
    assert looks_like_private_key("id_rsa.pub") is False
    assert looks_like_private_key("authorized_keys") is False
    assert contains_private_key_header("-----BEGIN OPENSSH PRIVATE KEY-----\nabc") is True
    assert contains_private_key_header("ordinary text") is False


def test_parse_unit_preserves_duplicates_and_continuations() -> None:
    text = """[Unit]
Description=Example
[Service]
ExecStart=/bin/echo one \\
    two
ExecStart=/bin/echo three
[Install]
WantedBy=multi-user.target
"""
    sections = parse_unit(text)
    assert sections["Unit"]["Description"] == ["Example"]
    assert sections["Service"]["ExecStart"] == ["/bin/echo one two", "/bin/echo three"]
    assert ("ExecStart", "/bin/echo three") in unit_exec_lines(sections)
