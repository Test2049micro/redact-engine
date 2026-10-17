"""Redaction and the projection that is allowed to leave this process.

The privacy boundary here is structural, not declarative. A docstring that says
"never print raw text" is a wish; code that only ever *reads* the fields on a
whitelist cannot print raw text whatever the model asks for. So:

* ``project()`` touches a fixed set of keys. An unexpected key holding a chat log
  is not filtered out -- it is never looked at.
* text passes through :meth:`Redactor.redact` before it can reach the output at
  all; there is no path that serialises an unredacted string.
* the reversible identity map exists only behind an explicit flag, is written
  ``0600`` inside a ``0700`` directory, and is refused if the target is a symlink.
"""

from __future__ import annotations

import json
import os
import secrets as _secrets
import stat
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from .alias import check_key, make_alias, new_key
from .rules import DEFAULT_RULES, Rule

DEFAULT_FIELDS = ("timestamp", "app", "text")


@dataclass
class Hit:
    kind: str
    value: str
    alias: str


@dataclass
class Result:
    text: str
    hits: list[Hit] = field(default_factory=list)

    @property
    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for hit in self.hits:
            tally[hit.kind] = tally.get(hit.kind, 0) + 1
        return tally

    @property
    def redacted_values(self) -> list[str]:
        return [hit.value for hit in self.hits]


class Redactor:
    """Rule-driven redactor with stable or per-call aliasing.

    ``stable=False`` gives every run fresh aliases: the same subject becomes
    uncorrelatable across exports, which is what you want before anything leaves
    the machine. ``persist_map`` is the only mode that can be reversed, and it
    must be used with a key the caller controls.
    """

    def __init__(
        self,
        key: bytes,
        rules: Sequence[Rule] = DEFAULT_RULES,
        *,
        stable: bool = True,
        persist_map: Path | None = None,
    ) -> None:
        if stable:
            check_key(key)
        self._stable = stable
        self._key = key
        self._ephemeral: bytes | None = None
        self.rules = tuple(rules)
        self.persist_map = persist_map
        self.seen_values: list[str] = []
        self.all_hits: list[Hit] = []
        self.hit_counts: dict[str, int] = {}
        self._mapping: dict[tuple[str, str], str] = {}
        if persist_map is not None:
            self._load_map()

    def _active_key(self) -> bytes:
        if self._stable:
            return self._key
        if self._ephemeral is None:
            self._ephemeral = _secrets.token_bytes(32)
        return self._ephemeral

    def _lookup(self, kind: str, value: str) -> str:
        if self._stable and not self.persist_map:
            return make_alias(kind, value, self._active_key())
        token = (kind, value)
        if token not in self._mapping:
            self._mapping[token] = make_alias(kind, value, self._active_key())
            if self.persist_map:
                self._append_map(token, self._mapping[token])
        return self._mapping[token]

    def _load_map(self) -> None:
        target = Path(self.persist_map)
        if target.is_symlink():
            raise ValueError(f"refusing symlinked identity map: {target}")
        if not target.exists():
            return
        if not stat.S_ISREG(target.stat().st_mode):
            raise ValueError(f"identity map is not a regular file: {target}")
        descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            rows = json.loads(handle.read())
        for row in rows:
            self._mapping[(row["kind"], row["value"])] = row["alias"]

    def _append_map(self, token: tuple[str, str], label: str) -> None:
        target = Path(self.persist_map)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if target.is_symlink():
            raise ValueError(f"refusing to write an identity map through a symlink: {target}")
        rows = [dict(kind=k, value=v, alias=a) for (k, v), a in self._mapping.items()]
        # O_NOFOLLOW closes the check-then-use window: a symlink planted between the
        # existence check and this open would otherwise overwrite any file the user
        # can write, with the *full* identity map
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(rows, handle, ensure_ascii=False, indent=1)
        os.chmod(target, 0o600)

    def redact(self, text: str) -> Result:
        if not text:
            return Result(text=text)
        spans: list[tuple[int, int, str, str]] = []
        claimed: list[tuple[int, int]] = []
        for rule in self.rules:
            for match in rule.finditer(text):
                start, end = rule.span(match)
                if any(start < hi and lo < end for lo, hi in claimed):
                    continue  # an earlier, more specific rule already owns this span
                claimed.append((start, end))
                spans.append((start, end, rule.kind, rule.value(match)))
        spans.sort(key=lambda item: item[0])
        out = text
        hits: list[Hit] = []
        for start, end, kind, value in reversed(spans):
            label = self._lookup(kind, value)
            hits.append(Hit(kind=kind, value=value, alias=label))
            out = out[:start] + label + out[end:]
        for hit in hits:
            self.seen_values.append(hit.value)
            self.all_hits.append(hit)
            self.hit_counts[hit.kind] = self.hit_counts.get(hit.kind, 0) + 1
        return Result(text=out, hits=hits)

    def project(self, event: Mapping, fields: Sequence[str] = DEFAULT_FIELDS) -> dict:
        """Serialise only whitelisted fields, and run every string through redaction.

        There is no field type assumed to be safe: a client that stores a URL in
        ``app``, or a message in ``title``, is common enough that trusting field
        *names* would be the actual leak.
        """
        out: dict = {}
        for name in fields:
            if name not in event:
                continue
            value = event[name]
            if isinstance(value, (int, float, bool)) or value is None:
                out[name] = value
            else:
                # a dict/list is exactly where a recorder hides the sensitive part
                # (a nested note, a title, an ax blob), so it is flattened and then
                # redacted rather than serialised as-is
                out[name] = self.redact(_flatten(value)).text
        return out


_FLATTEN_LIMIT = 2000


def _flatten(value: object, limit: int = _FLATTEN_LIMIT) -> str:
    """Join nested structures into one redactable string.

    Kept local rather than importing the reader's helper: whatever arrives here
    must be flattened no matter which source produced it, or a nested note under a
    whitelisted field would serialise unredacted.
    """
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, list):
        return "\n".join(_flatten(item, limit) for item in value)[:limit]
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)[:limit]
    return str(value)[:limit]


MIN_VERIFY_LEN = 4


def leaked_kinds(payload: str, hits: Iterable[Hit]) -> dict[str, int]:
    """Which kinds survived, by count. Never returns the values themselves."""
    tally: dict[str, int] = {}
    for hit in hits:
        if len(hit.value) >= MIN_VERIFY_LEN and hit.value in payload:
            tally[hit.kind] = tally.get(hit.kind, 0) + 1
    return tally


def assert_no_leaks(payload: str, values: Iterable[str]) -> None:
    """Fail loudly if any pre-redaction value still appears in ``payload``.

    The message deliberately carries a count only. An error that quotes the
    surviving secret would leak it into the terminal, the log, and any CI artefact
    -- which is the one thing this check exists to prevent.
    """
    leaked = [value for value in values if value and len(value) >= MIN_VERIFY_LEN and value in payload]
    if leaked:
        raise LeakageError(f"{len(leaked)} pre-redaction value(s) survived into the output")


class LeakageError(AssertionError):
    pass
