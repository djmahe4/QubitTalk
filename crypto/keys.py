"""Key generation and passphrase-protected storage for Qubit Talks.

Standards: X25519 (RFC 7748), Ed25519 (RFC 8032), PKCS#8 PEM encryption (RFC 5958).
Classical keys only; ML-KEM / ML-DSA keys join here once liboqs is confirmed.
Private keys are stored encrypted with the user's passphrase and never logged.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

MIN_PASSPHRASE_CHARS = 8


class KeyFileError(ValueError):
    """Raised for weak passphrases, wrong passphrases, or malformed key files."""


@dataclass(frozen=True)
class UnlockedKeys:
    user_id: str
    x25519: X25519PrivateKey
    ed25519: Ed25519PrivateKey

    def public_json(self) -> bytes:
        return _public_json(self.user_id, self.x25519, self.ed25519)

    def fingerprint(self) -> str:
        return hashlib.sha256(self.public_json()).hexdigest()[:16]


def _raw_pub(key) -> str:
    raw = key.public_key().public_bytes(ser.Encoding.Raw, ser.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def _public_json(user_id: str, x_priv, e_priv) -> bytes:
    data = {
        "id": user_id,
        "x25519_pub": _raw_pub(x_priv),
        "ed25519_pub": _raw_pub(e_priv),
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _pem(key, passphrase: str) -> str:
    enc = ser.BestAvailableEncryption(passphrase.encode("utf-8"))
    return key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.PKCS8, enc).decode(
        "ascii"
    )


def generate(user_id: str, passphrase: str) -> tuple[bytes, bytes]:
    """Return (private_key_file, public_key_file) bytes for a new identity."""
    if not user_id.strip():
        raise KeyFileError("Name is required.")
    if len(passphrase) < MIN_PASSPHRASE_CHARS:
        raise KeyFileError(
            f"Passphrase must be at least {MIN_PASSPHRASE_CHARS} characters."
        )
    x_priv, e_priv = X25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    private = {
        "id": user_id,
        "x25519_pem": _pem(x_priv, passphrase),
        "ed25519_pem": _pem(e_priv, passphrase),
    }
    return json.dumps(private).encode("utf-8"), _public_json(user_id, x_priv, e_priv)


def unlock(private_file: bytes, passphrase: str) -> UnlockedKeys:
    """Decrypt a private key file with its passphrase."""
    try:
        data = json.loads(private_file.decode("utf-8"))
        pw = passphrase.encode("utf-8")
        x_priv = ser.load_pem_private_key(data["x25519_pem"].encode("ascii"), pw)
        e_priv = ser.load_pem_private_key(data["ed25519_pem"].encode("ascii"), pw)
        return UnlockedKeys(str(data["id"]), x_priv, e_priv)
    except (ValueError, KeyError, TypeError) as exc:
        raise KeyFileError(
            "Wrong passphrase or not a valid Qubit Talks key file."
        ) from exc
