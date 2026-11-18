"""Shared command-line and script patterns used by multiple collectors.

These patterns are deliberately narrow and paired with explicit false-positive
guidance in the rule catalog.  They identify *constructs*, never intent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandPattern:
    name: str
    regex: re.Pattern[str]
    description: str


def _pattern(name: str, expression: str, description: str) -> CommandPattern:
    return CommandPattern(name=name, regex=re.compile(expression, re.IGNORECASE), description=description)


SUSPICIOUS_PATTERNS: tuple[CommandPattern, ...] = (
    _pattern("dev_tcp", r"/dev/(?:tcp|udp)/", "Bash /dev/tcp pseudo-device used for network I/O"),
    _pattern("netcat_exec", r"\b(?:nc|ncat|netcat)\b[^\n]*\s-e\s", "Netcat configured to execute a program"),
    _pattern(
        "download_pipe_shell",
        r"\b(?:curl|wget)\b[^\n|;]*\|\s*(?:sudo\s+)?(?:ba|z|k|da)?sh\b",
        "Downloaded content piped directly into a shell",
    ),
    _pattern(
        "base64_pipe_shell",
        r"\bbase64\b[^\n|;]*\s(?:-d|--decode)\b[^\n|;]*\|\s*(?:ba|z|da)?sh\b",
        "Base64-decoded content piped directly into a shell",
    ),
    _pattern(
        "python_socket",
        r"\bpython[0-9.]*\b[^\n]*\s-c\s[^\n]*(?:socket|pty\.spawn)",
        "Inline Python using sockets or a spawned PTY",
    ),
    _pattern(
        "perl_socket",
        r"\bperl\b[^\n]*\s-e\s[^\n]*(?:IO::Socket|Socket)",
        "Inline Perl using a socket module",
    ),
    _pattern("socat_exec", r"\bsocat\b[^\n]*\bexec:", "socat configured to execute a program"),
    _pattern("bash_dev_tcp", r"\bbash\b[^\n]*-i[^\n]*>&\s*/dev/tcp/", "Interactive bash redirect to /dev/tcp"),
    _pattern("mkfifo_shell", r"\bmkfifo\b[^\n]*\|[^\n]*\b(?:ba)?sh\b", "Named pipe used to feed a shell"),
    _pattern("openssl_reverse", r"\bopenssl\b[^\n]*s_client[^\n]*\|", "OpenSSL client output piped to another process"),
    _pattern("history_clear", r"\bhistory\s+-c\b|rm\s+[^\n]*\.bash_history", "Shell history cleared or deleted"),
    _pattern(
        "log_tamper",
        r"\b(?:rm|truncate|shred)\b[^\n]*(?:/var/log|wtmp|btmp|lastlog)",
        "Log files deleted, truncated or shredded",
    ),
    _pattern("chattr_immutable", r"\bchattr\s+\+i\b", "File made immutable (may hinder response)"),
    _pattern("ld_preload_env", r"\bLD_PRELOAD\s*=", "LD_PRELOAD injection via environment"),
)


def match_patterns(text: str) -> list[dict[str, str]]:
    """Return every pattern that matches ``text`` as ``{name, description}``."""
    if not text:
        return []
    matches: list[dict[str, str]] = []
    for pattern in SUSPICIOUS_PATTERNS:
        if pattern.regex.search(text):
            matches.append({"name": pattern.name, "description": pattern.description})
    return matches


def has_suspicious_pattern(text: str) -> bool:
    return bool(match_patterns(text))
