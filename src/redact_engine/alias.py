"""Alias keys, and the file rules around them.

An alias is ``[kind-<first 12 hex of HMAC-SHA256(key, "kind:value")]>``. Two
properties are load-bearing:

* the key is *persistent*, so the same person keeps the same alias across runs --
  without that, a projection cannot answer any question that spans days. (This is
  the opposite of per-message pseudonymisation, which exists to *prevent*
  cross-request correlation. Choose deliberately; this layer is the one where you
  want it.)
* the ``kind`` is inside the message, so one value under two kinds yields two
  aliases, and a leaked alias for a URL cannot be replayed against an email.

The key file is the only thing that turns aliases back into identities. It is
created ``O_EXCL`` with mode ``0600``, and a key file that is a symlink or not
owned by the reader is refused rather than used quietly.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import stat
from pathlib import Path

KEY_BYTES = 32
ALIAS_HEX = 12


class InsecureKeyFile(RuntimeError):
    pass


def make_alias(kind: str, value: str, key: bytes) -> str:
    digest = hmac.new(key, f"{kind}:{value}".encode("utf-8"), hashlib.sha256).hexdigest()
    return f"[{kind}-{digest[:ALIAS_HEX]}]"


def check_key(key: bytes) -> None:
    if len(key) < KEY_BYTES:
        raise ValueError(f"alias key must be at least {KEY_BYTES} bytes, got {len(key)}")


def new_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def _assert_usable(path: Path) -> None:
    if path.is_symlink():
        raise InsecureKeyFile(f"refusing symlinked key file: {path}")
    if not path.exists():
        return
    info = path.stat()
    if not stat.S_ISREG(info.st_mode):
        raise InsecureKeyFile(f"key file is not a regular file: {path}")
    if info.st_uid != os.getuid():
        raise InsecureKeyFile(f"key file is not owned by the reader: {path}")
    if info.st_mode & 0o077:
        raise InsecureKeyFile(
            f"key file is readable by group or others (mode {oct(info.st_mode & 0o777)}): {path}"
        )


def load_key(path: str | Path) -> bytes:
    target = Path(path).expanduser()
    _assert_usable(target)
    descriptor = os.open(str(target), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read()
    finally:
        pass
    if len(data) < KEY_BYTES:
        raise InsecureKeyFile(f"key file is too short to be a key: {target}")
    return data


def create_key(path: str | Path, *, overwrite: bool = False) -> bytes:
    target = Path(path).expanduser()
    if target.is_symlink():
        raise InsecureKeyFile(f"refusing to write through a symlink: {target}")
    if target.exists() and not overwrite:
        raise InsecureKeyFile(f"key already exists, refusing to replace it: {target}")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL
                         | getattr(os, "O_NOFOLLOW", 0), 0o600)
    key = new_key()
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        target.unlink(missing_ok=True)
        raise
    os.chmod(target, 0o600)
    return key


def load_or_create(path: str | Path, *, overwrite: bool = False) -> tuple[bytes, bool]:
    """``(key, created)`` -- the caller reports which one it got."""
    target = Path(path).expanduser()
    if target.exists():
        return load_key(target), False
    return create_key(target, overwrite=overwrite), True
