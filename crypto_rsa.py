"""RSA-3072 key management and AES key wrapping for Cryptix.

* ``generate_keypair`` – RSA 3072-bit, exponent 65537.
* ``wrap_key`` / ``unwrap_key`` – OAEP with MGF1-SHA256 / SHA256, no label.
* ``serialize_public_key`` / ``load_public_key`` – PEM encoding.
* ``serialize_private_key`` / ``load_private_key`` – PKCS8 PEM encrypted
  with `BestAvailableEncryption(passphrase)`.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
    RSAPublicKey,
)

from core.errors import KeyUnwrapError, WrongPassphraseError


# ------------------------------------------------------------------
# Key generation
# ------------------------------------------------------------------

def generate_keypair() -> RSAPrivateKey:
    """Generate an RSA-3072 private key (public key is derivable)."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=3072,
    )


# ------------------------------------------------------------------
# OAEP wrap / unwrap
# ------------------------------------------------------------------

_OAEP_PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None,
)


def wrap_key(aes_key: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt *aes_key* under *public_key* using RSA-OAEP."""
    return public_key.encrypt(aes_key, _OAEP_PADDING)


def unwrap_key(wrapped: bytes, private_key: RSAPrivateKey) -> bytes:
    """Decrypt *wrapped* using *private_key*.

    Raises ``KeyUnwrapError`` on any failure (wrong key, corrupted
    ciphertext, etc.).
    """
    try:
        return private_key.decrypt(wrapped, _OAEP_PADDING)
    except Exception as exc:
        raise KeyUnwrapError(str(exc)) from exc


# ------------------------------------------------------------------
# PEM serialisation helpers
# ------------------------------------------------------------------

def serialize_public_key(public_key: RSAPublicKey) -> bytes:
    """Return *public_key* as PEM-encoded bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_public_key(data: bytes) -> RSAPublicKey:
    """Deserialise a PEM-encoded public key."""
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("Expected an RSA public key.")
    return key


def serialize_private_key(private_key: RSAPrivateKey, passphrase: bytes) -> bytes:
    """Return *private_key* as PKCS8 PEM encrypted with *passphrase*."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
    )


def load_private_key(data: bytes, passphrase: bytes) -> RSAPrivateKey:
    """Deserialise a PKCS8-PEM private key.

    Raises ``WrongPassphraseError`` if *passphrase* is incorrect.
    """
    try:
        key = serialization.load_pem_private_key(data, password=passphrase)
    except (ValueError, TypeError) as exc:
        raise WrongPassphraseError(str(exc)) from exc
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("Expected an RSA private key.")
    return key
