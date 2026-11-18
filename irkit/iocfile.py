"""Indicator-of-compromise file loading and validation.

Supports JSON (``{"indicators": [...]}`` or a bare list) and plain text.  All
values are validated and normalised; nothing is resolved over the network and
no indicator is ever uploaded anywhere.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from irkit.models import Severity

ALLOWED_TYPES = frozenset({"ip", "domain", "url", "sha256", "sha1", "md5", "path", "string"})
_HASH_LENGTHS = {"sha256": 64, "sha1": 40, "md5": 32}
_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_MAX_FILE_BYTES = 1024 * 1024
_MAX_INDICATORS = 1000


@dataclass(frozen=True)
class Indicator:
    type: str
    value: str
    severity: Severity
    description: str
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "value": self.value,
            "severity": self.severity.value,
            "description": self.description,
            "source": self.source,
        }


def detect_type(value: str) -> str:
    """Best-effort type detection for bare plain-text indicators."""
    candidate = value.strip()
    try:
        ipaddress.ip_address(candidate)
        return "ip"
    except ValueError:
        pass
    lowered = candidate.lower()
    if lowered.startswith(("http://", "https://")):
        return "url"
    if _HEX.match(candidate):
        length = len(candidate)
        for name, expected in _HASH_LENGTHS.items():
            if length == expected:
                return name
    if candidate.startswith("/"):
        return "path"
    if _DOMAIN.match(candidate):
        return "domain"
    return "string"


def normalise(indicator_type: str, value: str) -> tuple[str | None, str | None]:
    """Validate and normalise an indicator value.

    Returns ``(normalised_value, error)``.
    """
    kind = indicator_type.strip().lower()
    text = value.strip().strip('"').strip("'")
    if not text:
        return None, "empty indicator value"
    if kind not in ALLOWED_TYPES:
        return None, f"unsupported indicator type: {indicator_type!r}"
    if kind == "ip":
        try:
            return ipaddress.ip_address(text).compressed, None
        except ValueError:
            return None, f"invalid IP address: {text!r}"
    if kind == "domain":
        domain = text.lower().rstrip(".")
        if not _DOMAIN.match(domain):
            return None, f"invalid domain: {text!r}"
        return domain, None
    if kind == "url":
        lowered = text.lower()
        if not lowered.startswith(("http://", "https://")):
            return None, f"URL must use http(s): {text!r}"
        return text, None
    if kind in _HASH_LENGTHS:
        if len(text) != _HASH_LENGTHS[kind] or not _HEX.match(text):
            return None, f"invalid {kind} digest: {text!r}"
        return text.lower(), None
    if kind == "path":
        if not text.startswith("/"):
            return None, f"path indicator must be absolute: {text!r}"
        return text, None
    if kind == "string":
        if len(text) < 3:
            return None, "string indicators must be at least 3 characters"
        return text, None
    return None, f"unsupported indicator type: {indicator_type!r}"


def _parse_severity(value: Any, errors: list[str], label: str) -> Severity:
    if value is None or value == "":
        return Severity.HIGH
    try:
        return Severity.from_str(str(value))
    except ValueError:
        errors.append(f"{label}: invalid severity {value!r}; using high")
        return Severity.HIGH


def _from_mapping(item: dict[str, Any], source: str, errors: list[str]) -> Indicator | None:
    raw_value = item.get("value", item.get("indicator"))
    if not isinstance(raw_value, str) or not raw_value.strip():
        errors.append(f"{source}: indicator entry has no usable value")
        return None
    raw_type = item.get("type")
    indicator_type = str(raw_type).lower() if raw_type else detect_type(raw_value)
    normalised, error = normalise(indicator_type, raw_value)
    if error:
        errors.append(f"{source}: {error}")
        return None
    severity = _parse_severity(item.get("severity"), errors, source)
    description = str(item.get("description") or "").strip() or f"{indicator_type} indicator supplied by analyst"
    return Indicator(
        type=indicator_type,
        value=normalised or raw_value,
        severity=severity,
        description=description,
        source=str(item.get("source")) if item.get("source") else None,
    )


def load_indicators(path: str | Path) -> tuple[list[Indicator], list[str]]:
    """Load indicators from a JSON or plain-text file.

    Returns ``(indicators, errors)``.  A malformed line is reported and
    skipped; valid indicators are still returned.
    """
    target = Path(path)
    errors: list[str] = []
    try:
        raw = target.read_bytes()
    except (OSError, PermissionError) as exc:
        return [], [f"cannot read indicator file {target}: {type(exc).__name__}: {exc}"]
    if len(raw) > _MAX_FILE_BYTES:
        return [], [f"indicator file exceeds {_MAX_FILE_BYTES} bytes"]
    text = raw.decode("utf-8", errors="replace").strip()
    if not text:
        return [], ["indicator file is empty"]

    parsed: list[Indicator] = []
    if text.startswith("{") or text.startswith("["):
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            return [], [f"invalid JSON indicator file: {exc}"]
        items: list[Any]
        if isinstance(document, dict):
            items = document.get("indicators", [])
        elif isinstance(document, list):
            items = document
        else:
            return [], ["JSON indicator file must be an object or list"]
        if not isinstance(items, list):
            return [], ["'indicators' must be a list"]
        for index, item in enumerate(items):
            label = f"entry {index + 1}"
            if isinstance(item, str):
                item = {"value": item}
            if not isinstance(item, dict):
                errors.append(f"{label}: expected a string or object")
                continue
            indicator = _from_mapping(item, label, errors)
            if indicator:
                parsed.append(indicator)
    else:
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if " #" in stripped:
                stripped = stripped.split(" #", 1)[0].strip()
            label = f"line {line_number}"
            indicator_type: str | None = None
            value = stripped
            if ":" in stripped:
                head, tail = stripped.split(":", 1)
                if head.strip().lower() in ALLOWED_TYPES:
                    indicator_type = head.strip().lower()
                    value = tail.strip()
            if indicator_type is None:
                parts = stripped.split(None, 1)
                if len(parts) == 2 and parts[0].lower() in ALLOWED_TYPES:
                    indicator_type = parts[0].lower()
                    value = parts[1].strip()
            indicator_type = indicator_type or detect_type(value)
            normalised, error = normalise(indicator_type, value)
            if error:
                errors.append(f"{label}: {error}")
                continue
            parsed.append(
                Indicator(
                    type=indicator_type,
                    value=normalised or value,
                    severity=Severity.HIGH,
                    description=f"{indicator_type} indicator supplied by analyst",
                )
            )

    deduped: dict[tuple[str, str], Indicator] = {}
    for indicator in parsed:
        key = (indicator.type, indicator.value)
        existing = deduped.get(key)
        if existing is None or indicator.severity.rank > existing.severity.rank:
            deduped[key] = indicator
    result = list(deduped.values())[:_MAX_INDICATORS]
    if len(deduped) > _MAX_INDICATORS:
        errors.append(f"indicator list truncated to {_MAX_INDICATORS} entries")
    return result, errors
