"""Encrypt / decrypt pipeline for Cryptix.

Implements Flow 1 (encryption) and Flow 2 (decryption + verification) from
SPEC.md with progress callbacks, cancellation, and rollback semantics.
"""

from __future__ import annotations

import os
import re
import stat
import shutil
import tempfile
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Callable, List, Optional

from core.crypto_aes import (
    CHUNK_SIZE,
    decrypt_bytes,
    decrypt_stream,
    encrypt_bytes,
    encrypt_stream,
    generate_key,
)
from core.crypto_rsa import unwrap_key, wrap_key, load_public_key, serialize_public_key
from core.errors import AuthError, KeyUnwrapError, PathSafetyError, StorageError, TamperedError
from core.hashing import constant_time_equal, sha256_file
from core.keys import Session
from core.storage import (
    atomic_write_bytes,
    data_enc_path,
    key_enc_path,
    list_files,
    meta_json_path,
    read_meta,
    remove_entry,
    write_meta,
)

# ---------------------------------------------------------------------------
# Callback type aliases (for readability only)
# ---------------------------------------------------------------------------

EventCallback = Optional[Callable[[str, str], None]]
ProgressCallback = Optional[Callable[[float], None]]
CancelEvent = Optional[threading.Event]

# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class VerifyResult:
    """Outcome of a single decrypt-and-verify operation."""
    status: str  # "SAFE" or "TAMPERED"
    expected_hash: str
    actual_hash: str
    reason: str = ""
    file_id: str = ""
    dest_path: Optional[Path] = None


@dataclass
class FolderSummary:
    """Summary returned by ``encrypt_folder`` and single-file encryption jobs."""
    encrypted: int = 0
    skipped: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    originals_removed: int = 0
    originals_kept: list[str] = field(default_factory=list)
    file_ids: list[str] = field(default_factory=list)
    files: list[dict] = field(default_factory=list)
    locked_in_place: int = 0
    kept_unlocked: list[str] = field(default_factory=list)
    # Backward-compat: first file_id (for single-file encrypt), set by jobs.py
    file_id: str = ""


EncryptSummary = FolderSummary


@dataclass
class EntryInfo:
    """One entry returned by ``list_entries``."""
    name: str
    size: int
    sha256_prefix: str
    file_id: str


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def is_critical_path(path: Path | str, storage_dir: Path | str) -> bool:
    """True when path is a drive root, user home, Desktop, or secure_storage."""
    try:
        p_norm = Path(os.path.normcase(str(Path(path).resolve())))
        s_norm = Path(os.path.normcase(str(Path(storage_dir).resolve())))
        # Drive root or filesystem root
        if p_norm.parent == p_norm or len(p_norm.parts) <= 1:
            return True
        # User home
        home_norm = Path(os.path.normcase(str(Path.home().resolve())))
        if p_norm == home_norm:
            return True
        # Desktop
        desktop_norm = Path(os.path.normcase(str((Path.home() / "Desktop").resolve())))
        if p_norm == desktop_norm:
            return True
        # OneDrive Desktop
        onedrive_desktop = Path(os.path.normcase(str((Path.home() / "OneDrive" / "Desktop").resolve())))
        if p_norm == onedrive_desktop:
            return True
        # storage_dir itself, inside storage_dir, or parent of storage_dir
        if p_norm == s_norm or s_norm in p_norm.parents or p_norm in s_norm.parents:
            return True
        return False
    except Exception:
        return True


def _safe_unlink(path: Path) -> tuple[bool, str]:
    """Safely unlink a file, removing read-only attribute if necessary.
    Returns (success, reason_if_failed)."""
    try:
        try:
            path.unlink()
            return True, ""
        except PermissionError:
            import stat
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
            path.unlink()
            return True, ""
    except Exception as exc:
        return False, str(exc)


def _require_unlocked(session: Session) -> None:
    """Raise ``AuthError`` immediately if the session is locked."""
    if not session.is_unlocked:
        raise AuthError("Session is locked – unlock first.")


def _check_cancel(cancel: CancelEvent) -> None:
    if cancel is not None and cancel.is_set():
        raise InterruptedError("Operation cancelled.")


def _fire(cb: EventCallback, step: str, detail: str) -> None:
    if cb is not None:
        cb(step, detail)


def _progress(cb: ProgressCallback, frac: float) -> None:
    if cb is not None:
        cb(frac)


_PATH_TRAVERSAL_RE = re.compile(r"(^|[\\/])\.\.($|[\\/])")


def _validate_rel_path(rel: str) -> None:
    """Raise ``PathSafetyError`` if *rel* would escape its sandbox."""
    p = PurePosixPath(rel)
    # Absolute
    if p.is_absolute() or (len(rel) >= 2 and rel[1] == ":"):
        raise PathSafetyError(f"Absolute path rejected: {rel}")
    # Parent traversal
    if _PATH_TRAVERSAL_RE.search(rel) or ".." in p.parts:
        raise PathSafetyError(f"Path traversal rejected: {rel}")


def _safe_dest(dest_dir: Path, rel_name: str) -> Path:
    """Compute a non-overwriting destination path under *dest_dir*."""
    target = dest_dir / rel_name
    if target.exists():
        stem = target.stem
        suffix = target.suffix
        parent = target.parent
        counter = 1
        while True:
            candidate = parent / f"{stem}_{counter}{suffix}"
            if not candidate.exists():
                return candidate
            counter += 1
    return target


# ---------------------------------------------------------------------------
# encrypt_file
# ---------------------------------------------------------------------------

def encrypt_file(
    session: Session,
    file_path: Path | str,
    storage_dir: Path | str,
    rel_name: str | None = None,
    on_event: EventCallback = None,
    on_progress: ProgressCallback = None,
    cancel: CancelEvent = None,
    delete_original: bool = False,
    lock_in_place: bool = False,
) -> str:
    """Encrypt a single file into secure storage (Flow 1).

    Returns the ``file_id`` (UUID4 string) assigned to this entry.
    """
    _require_unlocked(session)
    file_path = Path(file_path)
    storage_dir = Path(storage_dir)

    if rel_name is None:
        rel_name = file_path.name

    file_id = str(uuid.uuid4())
    aes_key: Optional[bytes] = None

    try:
        _check_cancel(cancel)

        # 1. SHA-256 fingerprint of the original
        _progress(on_progress, 0.0)
        sha_hex = sha256_file(file_path)
        _fire(on_event, "sha256_hash", f"SHA-256 fingerprint created: {sha_hex[:12]}...")
        _progress(on_progress, 0.15)

        _check_cancel(cancel)

        # 2. AES encrypt
        _fire(on_event, "aes_encrypt", f"AES-256 file encrypted ({rel_name})")
        aes_key = generate_key()
        enc_path = data_enc_path(storage_dir, file_id)
        nonce_prefix = encrypt_stream(file_path, enc_path, aes_key, file_id, sha_hex)
        _progress(on_progress, 0.50)

        _check_cancel(cancel)

        # 3. RSA wrap the AES key with the public key
        _fire(on_event, "rsa_wrap_key", "AES key protected with RSA")
        pub = session.public_key(storage_dir)
        wrapped_key = wrap_key(aes_key, pub)
        _progress(on_progress, 0.55)

        _check_cancel(cancel)

        # 4. Encrypt original filename and absolute path
        name_enc = encrypt_bytes(rel_name.encode("utf-8"), aes_key)
        orig_path_enc = encrypt_bytes(str(file_path.absolute()).encode("utf-8"), aes_key)

        # 5. Store key.enc + meta.json
        _fire(on_event, "store", "Stored (file + protected key + hash)")
        atomic_write_bytes(key_enc_path(storage_dir, file_id), wrapped_key)
        file_size = file_path.stat().st_size
        write_meta(
            storage_dir,
            file_id,
            sha256=sha_hex,
            nonce_prefix=nonce_prefix,
            chunk_size=CHUNK_SIZE,
            size=file_size,
            name_enc=name_enc,
            orig_path_enc=orig_path_enc,
        )
        _progress(on_progress, 0.65)

        # Drop the AES key reference
        aes_key = None

        _check_cancel(cancel)

        # 6. Verify by decrypting to a temp location
        _fire(on_event, "verify", "Verified")
        vr = decrypt_file(
            session, file_id, storage_dir, _temp_verify_dir(storage_dir),
        )
        if vr.status != "SAFE":
            remove_entry(storage_dir, file_id)
            raise TamperedError(
                f"Post-encrypt verification failed: {vr.reason}"
            )
        # Clean up the verified temp file
        if vr.dest_path and vr.dest_path.exists():
            vr.dest_path.unlink(missing_ok=True)

        # 7. Re-hash the original and confirm it still equals the stored hash
        re_hash = sha256_file(file_path)
        if not constant_time_equal(re_hash, sha_hex):
            remove_entry(storage_dir, file_id)
            raise TamperedError(
                f"Original file was modified during encryption: {file_path.name}"
            )

        # 8. Only then lock in place or delete the original if requested and allowed
        if lock_in_place:
            _fire(on_event, "lock", "Original file locked in place")
            lock_file_in_place(file_path, storage_dir, file_id)
        elif delete_original:
            if not is_critical_path(file_path, storage_dir):
                _safe_unlink(file_path)

        _progress(on_progress, 1.0)

    except BaseException:
        aes_key = None
        remove_entry(storage_dir, file_id)
        raise

    return file_id


def lock_file_in_place(file_path: Path | str, storage_dir: Path | str, file_id: str) -> None:
    """Overwrites file in-place with its ciphertext, makes read-only, and renames to .encrypt."""
    file_path = Path(file_path)
    storage_dir = Path(storage_dir)
    enc_path = data_enc_path(storage_dir, file_id)
    
    if not file_path.exists() or not enc_path.exists():
        return

    locked_path = file_path.with_name(file_path.name + ".encrypt")
    
    # Fast approach: shutil.copy2 to new locked path
    shutil.copy2(enc_path, locked_path)
    
    # Make read-only
    try:
        locked_path.chmod(stat.S_IREAD)
    except Exception:
        pass
        
    # Remove original
    _safe_unlink(file_path)


def _temp_verify_dir(storage_dir: Path) -> Path:
    d = storage_dir / "_verify_tmp"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ---------------------------------------------------------------------------
# encrypt_folder
# ---------------------------------------------------------------------------

def encrypt_folder(
    session: Session,
    folder: Path | str,
    storage_dir: Path | str,
    on_event: EventCallback = None,
    on_progress: ProgressCallback = None,
    cancel: CancelEvent = None,
    delete_originals: bool = False,
    lock_in_place: bool = False,
) -> FolderSummary:
    """Recursively encrypt every file under *folder*.

    Skips and reports symlinks.  Includes empty, hidden, and unicode-named
    files.  Returns a ``FolderSummary``.
    """
    _require_unlocked(session)
    folder = Path(folder)
    storage_dir = Path(storage_dir)
    summary = FolderSummary()

    all_files: list[tuple[Path, str]] = []
    for root, dirs, files in os.walk(folder):
        root_path = Path(root)
        for name in files:
            full = root_path / name
            rel = full.relative_to(folder).as_posix()
            if full.is_symlink():
                summary.skipped.append(f"symlink: {rel}")
                continue
            all_files.append((full, rel))

    total = len(all_files)
    for idx, (full, rel) in enumerate(all_files):
        _check_cancel(cancel)
        try:
            file_size = full.stat().st_size
            sha_hex = sha256_file(full)

            fid = encrypt_file(
                session, full, storage_dir, rel_name=rel,
                on_event=on_event, cancel=cancel,
                delete_original=False,  # managed explicitly below
            )
            summary.encrypted += 1
            summary.file_ids.append(fid)
            summary.files.append({
                "name": rel,
                "sha256": sha_hex,
                "size": file_size,
            })

            if lock_in_place:
                if is_critical_path(full, storage_dir):
                    summary.kept_unlocked.append(f"{rel}: protected path cannot be locked")
                else:
                    try:
                        lock_file_in_place(full, storage_dir, fid)
                        summary.locked_in_place += 1
                    except Exception as err:
                        summary.kept_unlocked.append(f"{rel}: could not lock ({err})")
            elif delete_originals:
                if is_critical_path(full, storage_dir):
                    summary.originals_kept.append(f"{rel}: protected path cannot be deleted")
                else:
                    ok, err = _safe_unlink(full)
                    if ok:
                        summary.originals_removed += 1
                    else:
                        summary.originals_kept.append(f"{rel}: could not delete ({err})")

        except InterruptedError:
            raise
        except Exception as exc:
            summary.errors.append(f"{rel}: {exc}")

        if on_progress:
            on_progress((idx + 1) / max(total, 1))

    # Bottom-up cleanup of empty directories
    if delete_originals:
        for root, dirs, files in os.walk(folder, topdown=False):
            for d in dirs:
                sub_d = Path(root) / d
                try:
                    sub_d.rmdir()
                except OSError:
                    pass
        if not is_critical_path(folder, storage_dir):
            try:
                folder.rmdir()
            except OSError:
                pass  # not empty (skipped symlinks or failed files keep it)

    return summary


# ---------------------------------------------------------------------------
# decrypt_file
# ---------------------------------------------------------------------------

def decrypt_file(
    session: Session,
    file_id: str,
    storage_dir: Path | str,
    dest_dir: Path | str,
    on_event: EventCallback = None,
    on_progress: ProgressCallback = None,
    cancel: CancelEvent = None,
) -> VerifyResult:
    """Decrypt a single file and verify integrity (Flow 2).

    Returns a ``VerifyResult`` with status ``"SAFE"`` or ``"TAMPERED"``.
    """
    _require_unlocked(session)
    storage_dir = Path(storage_dir)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    meta = read_meta(storage_dir, file_id)
    expected_hash = meta["sha256"]
    nonce_prefix: bytes = meta["nonce_prefix"]
    name_enc: bytes = meta["name_enc"]

    _fire(on_event, "rsa_unwrap_key", "AES key recovered with RSA")
    _progress(on_progress, 0.0)
    wrapped = key_enc_path(storage_dir, file_id).read_bytes()
    aes_key = unwrap_key(wrapped, session.private_key)
    _progress(on_progress, 0.10)

    _check_cancel(cancel)

    # Decrypt the original relative path
    rel_name = decrypt_bytes(name_enc, aes_key).decode("utf-8")
    _validate_rel_path(rel_name)
    
    orig_path: Optional[Path] = None
    if "orig_path_enc" in meta:
        orig_path = Path(decrypt_bytes(meta["orig_path_enc"], aes_key).decode("utf-8"))

    # Build temp file path inside dest_dir
    fd, tmp_path_str = tempfile.mkstemp(dir=str(dest_dir), prefix=".cryptix_")
    os.close(fd)
    tmp_path = Path(tmp_path_str)

    try:
        _fire(on_event, "aes_decrypt", f"AES-256 file decrypted ({rel_name})")
        decrypt_stream(
            data_enc_path(storage_dir, file_id),
            tmp_path,
            aes_key,
            file_id,
            expected_hash,
            nonce_prefix,
        )
        _progress(on_progress, 0.60)

        _check_cancel(cancel)

        # SHA-256 the decrypted output
        actual_hash = sha256_file(tmp_path)
        _fire(on_event, "sha256_compare", f"SHA-256 recalculated: {actual_hash[:12]}...")
        _progress(on_progress, 0.85)

        if constant_time_equal(actual_hash, expected_hash):
            # SAFE – move to final destination
            if orig_path:
                locked_path = orig_path.with_name(orig_path.name + ".encrypt")
                if locked_path.exists():
                    try:
                        locked_path.chmod(stat.S_IWRITE)
                    except Exception:
                        pass
                    _safe_unlink(locked_path)
                    final = orig_path
                    final.parent.mkdir(parents=True, exist_ok=True)
                else:
                    final = _safe_dest(dest_dir, rel_name)
                    final.parent.mkdir(parents=True, exist_ok=True)
            else:
                final = _safe_dest(dest_dir, rel_name)
                final.parent.mkdir(parents=True, exist_ok=True)
                
            os.replace(str(tmp_path), str(final))
            _fire(on_event, "result", "Hash compared: SAFE")
            _progress(on_progress, 1.0)
            aes_key = None
            return VerifyResult(
                status="SAFE",
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                file_id=file_id,
                dest_path=final,
            )
        else:
            # TAMPERED – delete the temp file
            tmp_path.unlink(missing_ok=True)
            _fire(on_event, "result", "Hash compared: TAMPERED")
            aes_key = None
            return VerifyResult(
                status="TAMPERED",
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                reason="SHA-256 mismatch after decryption",
                file_id=file_id,
            )

    except TamperedError as exc:
        tmp_path.unlink(missing_ok=True)
        _fire(on_event, "result", "Hash compared: TAMPERED")
        aes_key = None
        return VerifyResult(
            status="TAMPERED",
            expected_hash=expected_hash,
            actual_hash="",
            reason=str(exc),
            file_id=file_id,
        )
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        aes_key = None
        raise


# ---------------------------------------------------------------------------
# decrypt_all
# ---------------------------------------------------------------------------

def decrypt_all(
    session: Session,
    storage_dir: Path | str,
    dest_dir: Path | str,
    on_event: EventCallback = None,
    on_progress: ProgressCallback = None,
    cancel: CancelEvent = None,
) -> list[VerifyResult]:
    """Decrypt every file in the secure storage into *dest_dir*."""
    _require_unlocked(session)
    storage_dir = Path(storage_dir)
    ids = list_files(storage_dir)
    results: list[VerifyResult] = []
    total = len(ids)
    for idx, fid in enumerate(ids):
        _check_cancel(cancel)
        vr = decrypt_file(session, fid, storage_dir, dest_dir,
                          on_event=on_event, cancel=cancel)
        results.append(vr)
        if on_progress:
            on_progress((idx + 1) / max(total, 1))
    return results


# ---------------------------------------------------------------------------
# list_entries (decrypts names for display)
# ---------------------------------------------------------------------------

def list_entries(
    session: Session,
    storage_dir: Path | str,
) -> list[EntryInfo]:
    """Return metadata for every file in the storage.

    Requires an unlocked session to decrypt the original filenames.
    """
    _require_unlocked(session)
    storage_dir = Path(storage_dir)

    entries: list[EntryInfo] = []

    for fid in list_files(storage_dir):
        meta = read_meta(storage_dir, fid)
        wrapped = key_enc_path(storage_dir, fid).read_bytes()
        aes_key = unwrap_key(wrapped, session.private_key)
        name = decrypt_bytes(meta["name_enc"], aes_key).decode("utf-8")
        entries.append(EntryInfo(
            name=name,
            size=meta["size"],
            sha256_prefix=meta["sha256"][:16],
            file_id=fid,
        ))
        aes_key = None

    return entries


# ---------------------------------------------------------------------------
# export_public_key
# ---------------------------------------------------------------------------

def export_public_key(storage_dir: Path | str, out_path: Path | str) -> None:
    """Copy the public key PEM from *storage_dir*/keys/ to *out_path*.

    This allows sharing the public key with others so they can receive
    shared files.
    """
    storage_dir = Path(storage_dir)
    out_path = Path(out_path)
    pub_pem = (storage_dir / "keys" / "public.pem").read_bytes()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write_bytes(out_path, pub_pem)


# ---------------------------------------------------------------------------
# share_file
# ---------------------------------------------------------------------------

def share_file(
    session: Session,
    file_id: str,
    storage_dir: Path | str,
    recipient_public_pem: bytes,
    out_dir: Path | str,
) -> None:
    """Create a shareable bundle of an encrypted file for a recipient.

    1. RSA-unwrap the AES key with the owner's private key.
    2. Re-wrap the AES key with the *recipient*'s public key.
    3. Copy ``data.enc`` and ``meta.json`` unchanged, write the new
       ``key.enc`` into *out_dir*.

    The file data is **not** re-encrypted.
    """
    _require_unlocked(session)
    storage_dir = Path(storage_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # 1. Unwrap AES key with owner's private key
    wrapped_owner = key_enc_path(storage_dir, file_id).read_bytes()
    aes_key = unwrap_key(wrapped_owner, session.private_key)

    # 2. Re-wrap with recipient's public key
    recipient_pub = load_public_key(recipient_public_pem)
    wrapped_recipient = wrap_key(aes_key, recipient_pub)
    aes_key = None  # drop reference

    # 3. Copy data.enc and meta.json, write new key.enc
    import shutil
    src_data = data_enc_path(storage_dir, file_id)
    src_meta = meta_json_path(storage_dir, file_id)

    shutil.copy2(str(src_data), str(out_dir / "data.enc"))
    shutil.copy2(str(src_meta), str(out_dir / "meta.json"))
    atomic_write_bytes(out_dir / "key.enc", wrapped_recipient)


# ---------------------------------------------------------------------------
# decrypt_bundle
# ---------------------------------------------------------------------------

def decrypt_bundle(
    session: Session,
    bundle_dir: Path | str,
    dest_dir: Path | str,
    on_event: EventCallback = None,
    on_progress: ProgressCallback = None,
    cancel: CancelEvent = None,
) -> VerifyResult:
    """Decrypt a shared bundle (data.enc + key.enc + meta.json) into *dest_dir*.

    Uses the same verify pipeline as ``decrypt_file``.  The bundle directory
    is treated as a virtual single-file storage: we read meta.json to get the
    file_id and then perform the standard decrypt-and-verify flow.
    """
    _require_unlocked(session)
    bundle_dir = Path(bundle_dir)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Read meta.json from bundle
    meta_path = bundle_dir / "meta.json"
    if not meta_path.exists():
        raise StorageError(f"meta.json not found in bundle {bundle_dir}")
    import base64 as _b64
    import json as _json
    with open(meta_path, "r", encoding="utf-8") as fh:
        meta = _json.load(fh)
    meta["nonce_prefix"] = _b64.b64decode(meta["nonce_prefix"])
    meta["name_enc"] = _b64.b64decode(meta["name_enc"])

    file_id = meta["file_id"]
    expected_hash = meta["sha256"]
    nonce_prefix: bytes = meta["nonce_prefix"]
    name_enc: bytes = meta["name_enc"]

    _fire(on_event, "rsa_unwrap_key", "Unwrapping AES key")
    _progress(on_progress, 0.0)
    wrapped = (bundle_dir / "key.enc").read_bytes()
    aes_key = unwrap_key(wrapped, session.private_key)
    _progress(on_progress, 0.10)

    _check_cancel(cancel)

    # Decrypt the original relative path
    rel_name = decrypt_bytes(name_enc, aes_key).decode("utf-8")
    _validate_rel_path(rel_name)

    # Build temp file path inside dest_dir
    fd, tmp_path_str = tempfile.mkstemp(dir=str(dest_dir), prefix=".cryptix_")
    os.close(fd)
    tmp_path = Path(tmp_path_str)

    try:
        _fire(on_event, "aes_decrypt", f"Decrypting {rel_name}")
        decrypt_stream(
            bundle_dir / "data.enc",
            tmp_path,
            aes_key,
            file_id,
            expected_hash,
            nonce_prefix,
        )
        _progress(on_progress, 0.60)

        _check_cancel(cancel)

        _fire(on_event, "sha256_compare", "Verifying hash")
        actual_hash = sha256_file(tmp_path)
        _progress(on_progress, 0.85)

        if constant_time_equal(actual_hash, expected_hash):
            final = _safe_dest(dest_dir, rel_name)
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(str(tmp_path), str(final))
            _fire(on_event, "result", "SAFE")
            _progress(on_progress, 1.0)
            aes_key = None
            return VerifyResult(
                status="SAFE",
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                file_id=file_id,
                dest_path=final,
            )
        else:
            tmp_path.unlink(missing_ok=True)
            _fire(on_event, "result", "TAMPERED")
            aes_key = None
            return VerifyResult(
                status="TAMPERED",
                expected_hash=expected_hash,
                actual_hash=actual_hash,
                reason="SHA-256 mismatch after decryption",
                file_id=file_id,
            )

    except TamperedError as exc:
        tmp_path.unlink(missing_ok=True)
        _fire(on_event, "result", "TAMPERED")
        aes_key = None
        return VerifyResult(
            status="TAMPERED",
            expected_hash=expected_hash,
            actual_hash="",
            reason=str(exc),
            file_id=file_id,
        )
    except BaseException:
        tmp_path.unlink(missing_ok=True)
        aes_key = None
        raise


def verify_vault_integrity(
    session: Session,
    storage_dir: Path | str,
) -> list[dict]:
    """Verify integrity of all encrypted files in vault without releasing files."""
    _require_unlocked(session)
    storage_dir = Path(storage_dir)
    fids = list_files(storage_dir)
    results = []

    for fid in fids:
        try:
            meta = read_meta(storage_dir, fid)
            expected_hash = meta["sha256"]
            nonce_prefix = meta["nonce_prefix"]
            name_enc = meta["name_enc"]

            wrapped = key_enc_path(storage_dir, fid).read_bytes()
            aes_key = unwrap_key(wrapped, session.private_key)
            name = decrypt_bytes(name_enc, aes_key).decode("utf-8")

            fd, tmp_path_str = tempfile.mkstemp(prefix=".verify_vault_")
            os.close(fd)
            tmp_path = Path(tmp_path_str)

            try:
                decrypt_stream(
                    data_enc_path(storage_dir, fid),
                    tmp_path,
                    aes_key,
                    fid,
                    expected_hash,
                    nonce_prefix,
                )
                actual_hash = sha256_file(tmp_path)
                if constant_time_equal(actual_hash, expected_hash):
                    status = "SAFE"
                    reason = ""
                else:
                    status = "TAMPERED"
                    reason = "SHA-256 hash mismatch"
            except Exception as e:
                status = "TAMPERED"
                actual_hash = ""
                reason = str(e)
            finally:
                tmp_path.unlink(missing_ok=True)
                aes_key = None

            results.append({
                "file_id": fid,
                "name": name,
                "expected_hash": expected_hash,
                "actual_hash": actual_hash,
                "status": status,
                "reason": reason,
            })
        except Exception as exc:
            results.append({
                "file_id": fid,
                "name": fid,
                "expected_hash": "",
                "actual_hash": "",
                "status": "TAMPERED",
                "reason": str(exc),
            })

    return results

