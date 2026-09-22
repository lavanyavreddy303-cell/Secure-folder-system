"""Cryptix custom exceptions.

Every exception inherits from SecureFolderError so callers can catch
the entire family with a single except clause.
"""


class SecureFolderError(Exception):
    """Base exception for the Cryptix secure-folder system."""


class AuthError(SecureFolderError):
    """Generic authentication / authorisation failure."""


class WrongPassphraseError(AuthError):
    """The passphrase supplied to unlock a private key was incorrect."""


class LockedOutError(AuthError):
    """Too many failed unlock attempts; a delay must be observed."""


class KeyUnwrapError(SecureFolderError):
    """Failed to unwrap (decrypt) an AES key with RSA-OAEP."""


class TamperedError(SecureFolderError):
    """Ciphertext integrity check failed – data has been tampered with."""


class PathSafetyError(SecureFolderError):
    """A path component attempted to escape its sandbox (path traversal)."""


class StorageError(SecureFolderError):
    """Problem reading from or writing to the secure-storage directory."""
