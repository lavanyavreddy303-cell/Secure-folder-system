"""Secure-storage layout helpers for Cryptix.

Manages the on-disk layout::

    secure_storage/
      keys/public.pem, keys/private.pem
      files/<uuid4>/data.enc, key.enc, meta.json

Provides helpers for atomic writes, meta.json I/O, file listing, and
temp-file cleanup.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.errors import StorageError

# ---------------------------------------------------------------------------
# Layout helpers
# ---------------------------------------------------------------------------

def files_dir(storage_dir: Path) -> Path:
    """Return *storage_dir*/files, creating it if necessary."""
    d = storage_dir / "files"
    d.mkdir(parents=True, exist_ok=True)
    return d


def file_entry_dir(storage_dir: Path, file_id: str) -> Path:
    """Return files/<file_id>/ inside *storage_dir*, creating parents."""
    d = files_dir(storage_dir) / file_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_enc_path(storage_dir: Path, file_id: str) -> Path:
    return file_entry_dir(storage_dir, file_id) / "data.enc"


def key_enc_path(storage_dir: Path, file_id: str) -> Path:
    return file_entry_dir(storage_dir, file_id) / "key.enc"


def meta_json_path(storage_dir: Path, file_id: str) -> Path:
    return file_entry_dir(storage_dir, file_id) / "meta.json"


# ---------------------------------------------------------------------------
# Atomic write helper
# ---------------------------------------------------------------------------

def atomic_write_bytes(path: Path, data: bytes) -> None:
    """Write *data* to *path* atomically via a temp file + ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent))
    try:
        os.write(fd, data)
        os.close(fd)
        os.replace(tmp, str(path))
    except BaseException:
        os.close(fd) if not _fd_closed(fd) else None
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _fd_closed(fd: int) -> bool:
    """Check if a file descriptor has already been closed."""
    try:
        os.fstat(fd)
        return False
    except OSError:
        return True


# ---------------------------------------------------------------------------
# meta.json I/O
# ---------------------------------------------------------------------------

META_VERSION: int = 1


def write_meta(
    storage_dir: Path,
    file_id: str,
    *,
    sha256: str,
    nonce_prefix: bytes,
    chunk_size: int,
    size: int,
    name_enc: bytes,
    orig_path_enc: Optional[bytes] = None,
) -> None:
    """Write meta.json for *file_id* atomically."""
    meta: dict[str, Any] = {
        "version": META_VERSION,
        "file_id": file_id,
        "sha256": sha256,
        "nonce_prefix": base64.b64encode(nonce_prefix).decode("ascii"),
        "chunk_size": chunk_size,
        "size": size,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "name_enc": base64.b64encode(name_enc).decode("ascii"),
    }
    if orig_path_enc:
        meta["orig_path_enc"] = base64.b64encode(orig_path_enc).decode("ascii")
    payload = json.dumps(meta, indent=2).encode("utf-8")
    atomic_write_bytes(meta_json_path(storage_dir, file_id), payload)


def read_meta(storage_dir: Path, file_id: str) -> dict[str, Any]:
    """Read and parse meta.json for *file_id*.

    Returns a dict with ``nonce_prefix`` and ``name_enc`` already decoded
    from base-64 back to ``bytes``.
    """
    p = meta_json_path(storage_dir, file_id)
    if not p.exists():
        raise StorageError(f"meta.json not found for file_id={file_id}")
    with open(p, "r", encoding="utf-8") as fh:
        meta = json.load(fh)
    meta["nonce_prefix"] = base64.b64decode(meta["nonce_prefix"])
    meta["name_enc"] = base64.b64decode(meta["name_enc"])
    if "orig_path_enc" in meta:
        meta["orig_path_enc"] = base64.b64decode(meta["orig_path_enc"])
    return meta


# ---------------------------------------------------------------------------
# Listing
# ---------------------------------------------------------------------------

def list_files(storage_dir: Path) -> list[str]:
    """Return a sorted list of file_id strings present in the storage."""
    fd = files_dir(storage_dir)
    if not fd.exists():
        return []
    return sorted(
        d.name
        for d in fd.iterdir()
        if d.is_dir() and (d / "meta.json").exists()
    )


# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

def remove_entry(storage_dir: Path, file_id: str) -> None:
    """Remove files/<file_id>/ entirely (best-effort)."""
    d = files_dir(storage_dir) / file_id
    if d.exists():
        shutil.rmtree(d, ignore_errors=True)


def cleanup_temp_files(directory: Path, prefix: str = "tmp") -> None:
    """Remove temp files left behind by failed operations."""
    if not directory.exists():
        return
    for p in directory.iterdir():
        if p.is_file() and p.name.startswith(prefix):
            try:
                p.unlink()
            except OSError:
                pass
