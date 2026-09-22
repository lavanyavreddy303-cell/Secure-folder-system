"""AES-256-GCM streaming encryption and decryption for Cryptix.

Chunk layout
~~~~~~~~~~~~
* Plaintext is read in 1 MiB chunks.
* Each chunk is independently encrypted with AES-256-GCM.
* Nonce (12 bytes) = 8-byte random prefix + 4-byte big-endian chunk counter.
* AAD  = file_id (bytes) + chunk_index (4 BE) + final_flag (1 byte) + sha256_hex (bytes).
* Ciphertext on disk per chunk = encrypted_data + 16-byte GCM tag.
* Empty files produce exactly one final chunk of zero-length plaintext.

Helpers ``encrypt_bytes`` / ``decrypt_bytes`` provide simple AES-GCM with a
random 12-byte nonce for encrypting small values such as filenames.
"""

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.errors import TamperedError

CHUNK_SIZE: int = 1 << 20  # 1 MiB
_TAG_SIZE: int = 16
_NONCE_PREFIX_LEN: int = 8
_COUNTER_LEN: int = 4


# ------------------------------------------------------------------
# Key generation
# ------------------------------------------------------------------

def generate_key() -> bytes:
    """Return 32 cryptographically-random bytes (AES-256 key)."""
    return os.urandom(32)


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _make_nonce(prefix: bytes, counter: int) -> bytes:
    """Build a 12-byte nonce from an 8-byte *prefix* and a chunk *counter*."""
    return prefix + struct.pack(">I", counter)


def _make_aad(file_id: bytes, chunk_index: int, is_final: bool, sha256_hex: str) -> bytes:
    """Build the Associated Authenticated Data for a single chunk."""
    return (
        file_id
        + struct.pack(">I", chunk_index)
        + (b"\x01" if is_final else b"\x00")
        + sha256_hex.encode("ascii")
    )


# ------------------------------------------------------------------
# Streaming encrypt / decrypt
# ------------------------------------------------------------------

def encrypt_stream(
    in_path: Path | str,
    out_path: Path | str,
    key: bytes,
    file_id: str,
    sha256_hex: str,
) -> bytes:
    """Encrypt *in_path* into *out_path* using AES-256-GCM (1 MiB chunks).

    Returns the 8-byte random nonce prefix used for this encryption.
    The output file is written atomically via a temporary file + ``os.replace``.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    file_id_bytes = file_id.encode("utf-8")
    nonce_prefix = os.urandom(_NONCE_PREFIX_LEN)
    aes = AESGCM(key)

    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(out_dir))
    try:
        with open(in_path, "rb") as fin, os.fdopen(fd, "wb") as fout:
            chunk_index = 0
            while True:
                plaintext = fin.read(CHUNK_SIZE)
                # Peek ahead to know if this is the final chunk.
                next_byte = fin.read(1)
                is_final = len(next_byte) == 0
                if not is_final:
                    # Put the peeked byte back via seek.
                    fin.seek(-1, 1)

                nonce = _make_nonce(nonce_prefix, chunk_index)
                aad = _make_aad(file_id_bytes, chunk_index, is_final, sha256_hex)
                ct = aes.encrypt(nonce, plaintext, aad)  # ct includes tag
                fout.write(ct)

                if is_final:
                    break
                chunk_index += 1

        os.replace(tmp_name, str(out_path))
    except BaseException:
        # Clean up the temp file on any failure.
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise

    return nonce_prefix


def decrypt_stream(
    in_path: Path | str,
    out_path: Path | str,
    key: bytes,
    file_id: str,
    sha256_hex: str,
    nonce_prefix: bytes,
) -> None:
    """Decrypt *in_path* (written by ``encrypt_stream``) into *out_path*.

    *out_path* should be a temporary path chosen by the caller; this
    function writes to it directly (no extra temp-file indirection).

    Raises ``TamperedError`` on any integrity failure including truncation.
    """
    in_path = Path(in_path)
    out_path = Path(out_path)
    file_id_bytes = file_id.encode("utf-8")
    aes = AESGCM(key)

    ct_chunk_size = CHUNK_SIZE + _TAG_SIZE

    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(in_path, "rb") as fin, open(out_path, "wb") as fout:
        chunk_index = 0
        while True:
            ct = fin.read(ct_chunk_size)

            if len(ct) == 0:
                # We ran out of data without seeing a final chunk.
                raise TamperedError("Ciphertext is truncated (no final chunk).")

            # Peek to detect whether more ciphertext follows.
            next_byte = fin.read(1)
            is_final = len(next_byte) == 0
            if not is_final:
                fin.seek(-1, 1)

            # A non-final chunk must be exactly ct_chunk_size bytes.
            if not is_final and len(ct) < ct_chunk_size:
                raise TamperedError("Ciphertext chunk is truncated.")

            nonce = _make_nonce(nonce_prefix, chunk_index)
            aad = _make_aad(file_id_bytes, chunk_index, is_final, sha256_hex)

            try:
                plaintext = aes.decrypt(nonce, ct, aad)
            except InvalidTag:
                raise TamperedError(
                    f"Integrity check failed on chunk {chunk_index}."
                )

            fout.write(plaintext)

            if is_final:
                break
            chunk_index += 1


# ------------------------------------------------------------------
# Small-value helpers (e.g. filename encryption)
# ------------------------------------------------------------------

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    """Encrypt *data* with AES-256-GCM using a random 12-byte nonce.

    Returns ``nonce + ciphertext_with_tag``.
    """
    nonce = os.urandom(12)
    aes = AESGCM(key)
    ct = aes.encrypt(nonce, data, None)
    return nonce + ct


def decrypt_bytes(token: bytes, key: bytes) -> bytes:
    """Decrypt *token* produced by ``encrypt_bytes``.

    Raises ``TamperedError`` on integrity failure.
    """
    if len(token) < 12 + _TAG_SIZE:
        raise TamperedError("Token too short to contain nonce + tag.")
    nonce = token[:12]
    ct = token[12:]
    aes = AESGCM(key)
    try:
        return aes.decrypt(nonce, ct, None)
    except InvalidTag:
        raise TamperedError("Small-value decryption integrity check failed.")
