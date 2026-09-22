"""SHA-256 hashing utilities for Cryptix.

* ``sha256_file``  – streams a file in 1 MiB blocks.
* ``sha256_bytes`` – hashes an in-memory ``bytes`` object.
* ``constant_time_equal`` – timing-safe comparison via ``hmac.compare_digest``.
"""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

_CHUNK_SIZE: int = 1 << 20  # 1 MiB


def sha256_file(path: Path | str) -> str:
    """Return the SHA-256 hex digest of the file at *path*.

    The file is read in 1 MiB blocks so that arbitrarily large files
    can be hashed without loading them entirely into memory.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(_CHUNK_SIZE)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def sha256_bytes(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def constant_time_equal(a: str | bytes, b: str | bytes) -> bool:
    """Timing-safe equality check (delegates to ``hmac.compare_digest``)."""
    return hmac.compare_digest(a, b)
