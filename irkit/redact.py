"""Credential and secret redaction.

Redaction is applied to every serialised artefact (evidence JSON, HTML report
and JSON report).  It is intentionally conservative: it targets well-known
secret shapes and sensitive key/value pairs, and never touches SHA-256 digests
or other forensic identifiers.
"""

from __future__ import annotations

import re
from typing import Any

REDACTED = "[REDACTED]"

_SENSITIVE_KEYS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "secret",
        "clientsecret",
        "token",
        "authtoken",
        "accesstoken",
        "refreshtoken",
        "apikey",
        "accesskey",
        "secretkey",
        "privatekey",
        "sessionid",
        "cookie",
        "credentials",
        "credential",
        "authorization",
    }
)

_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----", re.DOTALL),
        "-----BEGIN PRIVATE KEY----- " + REDACTED + " -----END PRIVATE KEY-----",
    ),
    (
        re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|session[_-]?id|passphrase)\b(\s*[:=]\s*)([\"']?)([^\s\"',;]+)"),
        lambda match: f"{match.group(1)}{match.group(2)}{match.group(3)}{REDACTED}",
    ),
    (
        # Long command-line options only.  A single hyphen would also match
        # prose such as "empty-password and ..." and redact the next word.
        re.compile(
            r"(?i)(?<![\w-])(--(?:password|passwd|pass|token|api-key|apikey|secret)\s+)(\S+)"
        ),
        lambda match: f"{match.group(1)}{REDACTED}",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), REDACTED),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), REDACTED),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        REDACTED,
    ),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{8,}=*"), f"Bearer {REDACTED}"),
    (re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^/\s:@]+:)([^/\s@]+)(@)"), lambda m: f"{m.group(1)}{REDACTED}{m.group(3)}"),
)


def _key_is_sensitive(key: str) -> bool:
    normalised = re.sub(r"[^a-z0-9]", "", key.lower())
    return normalised in _SENSITIVE_KEYS


def redact_text(text: str) -> str:
    """Scrub known secret shapes from a string."""
    if not text:
        return text
    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)
    return result


def redact_obj(value: Any) -> Any:
    """Recursively redact strings inside JSON-compatible structures.

    Keys are preserved.  When a key is itself sensitive, its entire value is
    replaced, because a short or unusual secret would not match a pattern.
    """
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        cleaned: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _key_is_sensitive(key):
                cleaned[key] = REDACTED
            else:
                cleaned[key] = redact_obj(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [redact_obj(item) for item in value]
    return value
