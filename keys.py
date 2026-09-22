"""Key management and session control for Cryptix.

* ``init_user``  – generate and persist an RSA-3072 keypair.
* ``Session``    – unlock / lock the private key with passphrase-based
  authentication, failed-attempt rate-limiting, and auto-lock on inactivity.
"""

from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Callable, Optional

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from core.crypto_rsa import (
    generate_keypair,
    load_private_key,
    load_public_key,
    serialize_private_key,
    serialize_public_key,
)
from core.errors import AuthError, WrongPassphraseError
from core.storage import atomic_write_bytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MIN_PASSPHRASE_LEN: int = 10
_AUTO_LOCK_SECONDS: float = 300.0  # 5 minutes
_MAX_DELAY: float = 60.0

# ---------------------------------------------------------------------------
# Helpers – attempt counter persistence
# ---------------------------------------------------------------------------

def _attempts_path(storage_dir: Path) -> Path:
    return storage_dir / "keys" / "attempts.json"


def _read_attempts(storage_dir: Path) -> int:
    p = _attempts_path(storage_dir)
    if not p.exists():
        return 0
    with open(p, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return int(data.get("failed_attempts", 0))


def _write_attempts(storage_dir: Path, count: int) -> None:
    p = _attempts_path(storage_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as fh:
        json.dump({"failed_attempts": count}, fh)


def _delay_for_attempt(attempt_number: int) -> float:
    """Return the delay in seconds *before* attempt number ``attempt_number``.

    attempt_number is 1-based (1 = first failed attempt that just happened).
    The delay is 2^(n-1) seconds, capped at 60 s.
    """
    if attempt_number <= 0:
        return 0.0
    return min(2.0 ** (attempt_number - 1), _MAX_DELAY)


# ---------------------------------------------------------------------------
# chmod helper (best-effort on Windows)
# ---------------------------------------------------------------------------

def _chmod_600(path: Path) -> None:
    """Set file permissions to owner-read/write only, where supported."""
    try:
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        # Windows doesn't support POSIX permissions – silently ignore.
        pass


# ---------------------------------------------------------------------------
# init_user
# ---------------------------------------------------------------------------

def init_user(storage_dir: Path | str, passphrase: str) -> None:
    """Generate an RSA-3072 keypair and write it to *storage_dir*/keys/.

    * The passphrase must be at least 10 characters; raises ``AuthError``
      otherwise.
    * Refuses to overwrite existing key files (raises ``FileExistsError``).
    * Sets chmod 600 on the private key where the OS supports it.
    """
    if len(passphrase) < _MIN_PASSPHRASE_LEN:
        raise AuthError(
            f"Passphrase must be at least {_MIN_PASSPHRASE_LEN} characters."
        )

    storage_dir = Path(storage_dir)
    keys_dir = storage_dir / "keys"
    pub_path = keys_dir / "public.pem"
    priv_path = keys_dir / "private.pem"

    if pub_path.exists() or priv_path.exists():
        raise FileExistsError("Key files already exist; refusing to overwrite.")

    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key = generate_keypair()
    pub_pem = serialize_public_key(private_key.public_key())
    priv_pem = serialize_private_key(private_key, passphrase.encode("utf-8"))

    pub_path.write_bytes(pub_pem)
    priv_path.write_bytes(priv_pem)
    _chmod_600(priv_path)


def change_passphrase(storage_dir: Path | str, old_passphrase: str, new_passphrase: str) -> None:
    """Change the passphrase by re-encrypting the existing private key.
    
    Loads the private key using *old_passphrase*. Rate-limiting applies
    to the old passphrase just like unlocking. Re-encrypts the private key
    with *new_passphrase* and atomically writes it.
    """
    if len(new_passphrase) < _MIN_PASSPHRASE_LEN:
        raise AuthError(f"New passphrase must be at least {_MIN_PASSPHRASE_LEN} characters.")
    if new_passphrase == old_passphrase:
        raise AuthError("New passphrase must be different from the current one.")

    storage_dir = Path(storage_dir)
    priv_path = storage_dir / "keys" / "private.pem"

    failed = _read_attempts(storage_dir)
    if failed > 0:
        delay = _delay_for_attempt(failed)
        time.sleep(delay)

    priv_pem = priv_path.read_bytes()

    try:
        key = load_private_key(priv_pem, old_passphrase.encode("utf-8"))
    except WrongPassphraseError:
        _write_attempts(storage_dir, failed + 1)
        raise

    # Success: reset attempts
    _write_attempts(storage_dir, 0)

    # Re-encrypt with new passphrase
    new_priv_pem = serialize_private_key(key, new_passphrase.encode("utf-8"))
    atomic_write_bytes(priv_path, new_priv_pem)
    _chmod_600(priv_path)


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class Session:
    """Holds an unlocked RSA private key in memory with auto-lock support.

    Parameters
    ----------
    clock:
        A callable returning the current time as a float (seconds since
        epoch).  Defaults to ``time.time``; inject a fake clock in tests.
    sleep_fn:
        A callable equivalent to ``time.sleep``; inject a mock in tests.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.time,
        sleep_fn: Optional[Callable[[float], None]] = None,
    ) -> None:
        self._clock = clock
        self._sleep_fn = sleep_fn
        self._private_key: Optional[RSAPrivateKey] = None
        self._last_activity: float = 0.0

    # -- unlock / lock ---------------------------------------------------

    def unlock(self, storage_dir: Path | str, passphrase: str) -> None:
        """Load and decrypt the private key from *storage_dir*/keys/.

        On failure the persisted attempt counter is incremented and a
        rate-limiting delay is imposed *before* raising
        ``WrongPassphraseError``.  On success the counter is reset to 0.
        """
        storage_dir = Path(storage_dir)
        priv_path = storage_dir / "keys" / "private.pem"

        failed = _read_attempts(storage_dir)

        # Apply delay for the *upcoming* attempt if there have been prior
        # failures.  Delay = 2^(failed-1) for failed >= 1.
        if failed > 0:
            delay = _delay_for_attempt(failed)
            if self._sleep_fn is not None:
                self._sleep_fn(delay)
            else:
                time.sleep(delay)

        priv_pem = priv_path.read_bytes()

        try:
            key = load_private_key(priv_pem, passphrase.encode("utf-8"))
        except WrongPassphraseError:
            _write_attempts(storage_dir, failed + 1)
            raise

        # Success – reset counter and store key.
        _write_attempts(storage_dir, 0)
        self._private_key = key
        self._last_activity = self._clock()

    def lock(self) -> None:
        """Drop the private key reference."""
        self._private_key = None

    # -- properties ------------------------------------------------------

    @property
    def is_unlocked(self) -> bool:
        """``True`` if a private key is currently held in memory."""
        return self._private_key is not None

    @property
    def private_key(self) -> RSAPrivateKey:
        """Return the unlocked private key or raise ``AuthError``."""
        if self._private_key is None:
            raise AuthError("Session is locked – unlock first.")
        return self._private_key

    def public_key(self, storage_dir: Path | str) -> RSAPublicKey:
        """Load and return the public key from *storage_dir*/keys/public.pem.

        This never requires the session to be unlocked.
        """
        pub_path = Path(storage_dir) / "keys" / "public.pem"
        return load_public_key(pub_path.read_bytes())

    # -- auto-lock -------------------------------------------------------

    def touch(self) -> None:
        """Record user activity (resets the inactivity timer)."""
        self._last_activity = self._clock()

    def is_expired(self) -> bool:
        """Return ``True`` if more than 300 s have passed since the last
        ``touch()`` or ``unlock()``."""
        if not self.is_unlocked:
            return False
        return (self._clock() - self._last_activity) >= _AUTO_LOCK_SECONDS

    @classmethod
    def next_delay_seconds(cls, storage_dir: Path | str) -> int:
        """Read the persisted failed-attempt counter and return the delay 
        the next wrong attempt will incur (0 if none)."""
        storage_dir = Path(storage_dir)
        failed = _read_attempts(storage_dir)
        if failed > 0:
            return int(_delay_for_attempt(failed))
        return 0
