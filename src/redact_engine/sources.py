"""Event sources: the only part that knows what an activity stream looks like.

A source yields mappings; everything downstream is shape-agnostic. The field
mapping is what lets one engine read a JSONL recorder, an accessibility dump, or a
browser history export without the core knowing the difference -- which is the
point of separating them, because those shapes change per vendor and per release
while the redaction rules do not.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from pathlib import Path
from typing import Any

DEFAULT_MAPPING: dict[str, str] = {"timestamp": "timestamp", "app": "app", "text": "text"}


class UnsafeSource(RuntimeError):
    pass


def _check_regular(path: Path) -> None:
    if path.is_symlink():
        raise UnsafeSource(f"refusing symlinked source: {path}")
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise UnsafeSource(f"source is not a regular file: {path}")


def dig(payload: Any, dotted: str) -> Any:
    node = payload
    for part in dotted.split("."):
        if isinstance(node, list):
            try:
                node = node[int(part)]
                continue
            except (ValueError, IndexError):
                return None
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def flatten(value: Any, limit: int = 2000) -> str:
    """Join whatever a text field holds into one redactable string.

    Accessibility dumps store text as a list of lines, a nested dict, or a
    mixture; refusing to guess would drop the most sensitive content of all.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(flatten(item, limit) for item in value)[:limit]
    if isinstance(value, dict):
        if "text" in value and isinstance(value["text"], str):
            return value["text"][:limit]
        return json.dumps(value, ensure_ascii=False)[:limit]
    return str(value)[:limit]


def events_from_jsonl(
    path: str | Path,
    mapping: dict[str, str] | None = None,
    *,
    limit: int | None = None,
) -> Iterator[dict]:
    """Yield projected-shape events from a JSONL file.

    A malformed line is skipped and counted, not fatal: the point of a projector
    is that it survives a recorder that is mid-write, which is the normal state of
    a live activity stream.
    """
    mapping = mapping or DEFAULT_MAPPING
    target = Path(path).expanduser()
    _check_regular(target)
    produced = 0
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            event = {}
            for field, dotted in mapping.items():
                value = dig(payload, dotted) if dotted else None
                if value is None:
                    continue
                if isinstance(value, (int, float, bool)):
                    event[field] = value
                else:
                    # every non-scalar goes through flatten() so that a nested dict
                    # or list under *any* field name reaches the redactor
                    event[field] = flatten(value)
            yield event
            produced += 1
            if limit is not None and produced >= limit:
                return


def discover_segment_files(root: str | Path, pattern: str = "**/events.jsonl") -> list[Path]:
    """Sorted, symlink-free file list under a recording root."""
    base = Path(root).expanduser()
    if base.is_symlink():
        raise UnsafeSource(f"refusing symlinked recording root: {base}")
    if not base.is_dir():
        return []
    found = []
    for candidate in sorted(base.glob(pattern)):
        try:
            _check_regular(candidate)
        except OSError:
            continue
        found.append(candidate)
    return found
