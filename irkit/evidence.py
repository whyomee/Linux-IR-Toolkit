"""Evidence preservation with hash-on-collection.

The manager records *what was read*, when, and its SHA-256 digest.  It never
writes to, renames, quarantines or deletes source files.  Raw content is not
copied into the report; only parsed data and integrity metadata are stored.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from irkit.config import Limits, SystemPaths
from irkit.models import EvidenceItem
from irkit.utils import (
    canonical_json,
    file_metadata,
    iso_utc,
    sha256_file,
    sha256_text,
)

LOGGER = logging.getLogger(__name__)


class EvidenceManager:
    """Assign evidence IDs and preserve integrity metadata."""

    def __init__(self, paths: SystemPaths, limits: Limits, logger: logging.Logger | None = None) -> None:
        self.paths = paths
        self.limits = limits
        self.logger = logger or LOGGER
        self._items: list[EvidenceItem] = []
        self._index: dict[tuple[str, str, str | None, str | None], EvidenceItem] = {}
        self._counter = 0
        self.dropped = 0

    # -- public API --------------------------------------------------------
    @property
    def items(self) -> list[EvidenceItem]:
        return list(self._items)

    def record_file(
        self,
        path: Path | str,
        description: str,
        collector: str,
        *,
        hash_content: bool = True,
    ) -> EvidenceItem | None:
        """Record a file's metadata and, where possible, its SHA-256 digest."""
        target = Path(path)
        key = (collector, "file", str(target), None)
        if key in self._index:
            return self._index[key]
        if not self._has_capacity():
            return None

        metadata = file_metadata(target)
        notes: str | None = None
        digest: str | None = None
        content_size: int | None = None

        if "error" in metadata:
            notes = metadata["error"]
            readable = False
        else:
            readable = True
            if metadata.get("is_symlink"):
                try:
                    notes = f"symlink -> {target.resolve(strict=False)}"
                except OSError:
                    notes = "symlink (target unresolved)"
            if hash_content and not metadata.get("is_directory"):
                digest, content_size, hash_error = sha256_file(target, self.limits.max_hash_bytes)
                if hash_error:
                    notes = f"{notes}; {hash_error}" if notes else hash_error

        item = self._new_item(
            collector=collector,
            kind="file",
            source_path=str(target),
            description=description,
            metadata=metadata,
            sha256=digest,
            size=content_size if content_size else metadata.get("size"),
            notes=notes,
            readable=readable,
        )
        self._store(key, item)
        return item

    def record_directory(self, path: Path | str, description: str, collector: str) -> EvidenceItem | None:
        """Record a directory's metadata without hashing its contents."""
        target = Path(path)
        key = (collector, "directory", str(target), None)
        if key in self._index:
            return self._index[key]
        if not self._has_capacity():
            return None
        metadata = file_metadata(target)
        item = self._new_item(
            collector=collector,
            kind="directory",
            source_path=str(target),
            description=description,
            metadata=metadata,
            readable="error" not in metadata,
            notes=metadata.get("error"),
        )
        self._store(key, item)
        return item

    def record_command(
        self,
        command: str,
        stdout: str,
        description: str,
        collector: str,
        *,
        ok: bool = True,
        notes: str | None = None,
    ) -> EvidenceItem | None:
        """Record the output digest of a read-only command."""
        key = (collector, "command", command, None)
        if key in self._index:
            return self._index[key]
        if not self._has_capacity():
            return None
        item = self._new_item(
            collector=collector,
            kind="command",
            source_path=None,
            description=description,
            metadata={},
            sha256=sha256_text(stdout),
            size=len(stdout.encode("utf-8", errors="replace")),
            command=command,
            notes=notes or (None if ok else "command failed or returned non-zero"),
            readable=ok,
        )
        self._store(key, item)
        return item

    def record_data(
        self,
        label: str,
        payload: Any,
        description: str,
        collector: str,
    ) -> EvidenceItem | None:
        """Record a digest of structured data produced by an API or parser."""
        key = (collector, "data", label, None)
        if key in self._index:
            return self._index[key]
        if not self._has_capacity():
            return None
        encoded = canonical_json(payload)
        item = self._new_item(
            collector=collector,
            kind="data",
            source_path=label,
            description=description,
            metadata={},
            sha256=sha256_text(encoded),
            size=len(encoded.encode("utf-8", errors="replace")),
        )
        self._store(key, item)
        return item

    # -- internals ---------------------------------------------------------
    def _has_capacity(self) -> bool:
        if len(self._items) >= self.limits.max_evidence_items:
            self.dropped += 1
            if self.dropped == 1:
                self.logger.warning(
                    "evidence cap reached (%d items); further evidence metadata is dropped",
                    self.limits.max_evidence_items,
                )
            return False
        return True

    def _new_item(
        self,
        *,
        collector: str,
        kind: str,
        source_path: str | None,
        description: str,
        metadata: dict[str, Any],
        sha256: str | None = None,
        size: int | None = None,
        command: str | None = None,
        notes: str | None = None,
        readable: bool = True,
    ) -> EvidenceItem:
        self._counter += 1
        return EvidenceItem(
            evidence_id=f"E-{self._counter:05d}",
            collector=collector,
            kind=kind,
            source_path=source_path,
            description=description,
            collected_at=iso_utc(),
            sha256=sha256,
            size=size,
            mtime=metadata.get("mtime"),
            mode=metadata.get("mode"),
            owner=metadata.get("owner"),
            group=metadata.get("group"),
            command=command,
            notes=notes,
            readable=readable,
        )

    def _store(self, key: tuple[str, str, str | None, str | None], item: EvidenceItem) -> None:
        self._items.append(item)
        self._index[key] = item
