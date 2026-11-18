"""Tests for credential redaction."""

from __future__ import annotations

from irkit.redact import REDACTED, redact_obj, redact_text


def test_password_assignments_are_redacted() -> None:
    assert redact_text("password=hunter2") == f"password={REDACTED}"
    assert redact_text("secret: s3cr3t") == f"secret: {REDACTED}"
    assert redact_text("api_key = abc123") == f"api_key = {REDACTED}"


def test_command_line_secrets_are_redacted() -> None:
    assert redact_text("tool --password hunter2 --verbose") == f"tool --password {REDACTED} --verbose"
    assert redact_text("tool --token abc123") == f"tool --token {REDACTED}"


def test_prose_containing_password_is_not_over_redacted() -> None:
    text = "empty-password and lock state could not be verified"
    assert redact_text(text) == text


def test_private_key_block_is_redacted() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAAsecretAAAA\n-----END OPENSSH PRIVATE KEY-----"
    redacted = redact_text(text)
    assert "AAAAsecretAAAA" not in redacted
    assert REDACTED in redacted


def test_known_token_shapes_are_redacted() -> None:
    for token in (
        "AKIAABCDEFGHIJKLMNOP",
        "ghp_" + "a" * 24,
        "xoxb-1234567890-abcdef",
        "AIza" + "a" * 35,
        "Bearer abcdefghijkl",
        "https://user:pass@example.com/path",
    ):
        assert token.split(":")[-1] not in redact_text(token) or REDACTED in redact_text(token)


def test_sensitive_keys_replace_entire_value() -> None:
    payload = {
        "user": "alice",
        "password": "x",
        "nested": {"api_key": "tiny", "safe": "value"},
        "token": None,
    }
    cleaned = redact_obj(payload)
    assert cleaned["user"] == "alice"
    assert cleaned["password"] == REDACTED
    assert cleaned["nested"]["api_key"] == REDACTED
    assert cleaned["nested"]["safe"] == "value"
    assert cleaned["token"] == REDACTED


def test_digests_and_paths_are_preserved() -> None:
    payload = {
        "sha256": "a" * 64,
        "path": "/etc/passwd",
        "description": "hash-on-collection",
    }
    cleaned = redact_obj(payload)
    assert cleaned["sha256"] == "a" * 64
    assert cleaned["path"] == "/etc/passwd"
    assert cleaned["description"] == "hash-on-collection"


def test_lists_and_non_strings_are_handled() -> None:
    payload = {"items": ["password=abc", 5, None, {"secret": "value"}]}
    cleaned = redact_obj(payload)
    assert cleaned["items"][0] == f"password={REDACTED}"
    assert cleaned["items"][1] == 5
    assert cleaned["items"][2] is None
    assert cleaned["items"][3]["secret"] == REDACTED
