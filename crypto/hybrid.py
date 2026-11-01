"""Classical hybrid-ready encrypt/sign and verify/decrypt for Qubit Talks.

Standards: X25519 (RFC 7748), HKDF (RFC 5869), AES-256-GCM (NIST SP 800-38D),
Ed25519 (RFC 8032). This is the labelled CLASSICAL profile: kem_ciphertext is
empty and no post-quantum operation is claimed. ML-KEM / ML-DSA slot into the
same envelope fields later.

Flow: ephemeral X25519 + recipient public key -> HKDF -> AES-GCM key; the
sender's Ed25519 key signs every envelope field. Verify first, then decrypt.
"""

from __future__ import annotations

import base64
import binascii
import dataclasses
import json
import os

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.envelope import NONCE_LENGTH_BYTES, EncryptionEnvelope, EnvelopeAlgorithms
from crypto.keys import UnlockedKeys

VERSION = "1.0"
ALGORITHMS = EnvelopeAlgorithms("X25519", "AES-256-GCM", "Ed25519")


class CryptoError(ValueError):
    """Raised when verification or decryption fails; the message says why.

    `tampered` is True when the data itself was altered (as opposed to a wrong
    recipient, wrong sender file, or bad key file).
    """

    def __init__(self, message: str, tampered: bool = False):
        super().__init__(message)
        self.tampered = tampered


def _public_key(public_file: bytes, field: str) -> tuple[str, bytes]:
    try:
        data = json.loads(public_file.decode("utf-8"))
        return str(data["id"]), base64.b64decode(data[field], validate=True)
    except (ValueError, KeyError, TypeError, binascii.Error) as exc:
        raise CryptoError("Not a valid Qubit Talks public key file.") from exc


def _aead_key(
    shared_secret: bytes, sender_id: str, recipient_id: str
) -> tuple[AESGCM, bytes]:
    context = f"qubit-talks|{VERSION}|{sender_id}|{recipient_id}|{ALGORITHMS}".encode()
    key = HKDF(hashes.SHA256(), 32, salt=None, info=context).derive(shared_secret)
    return AESGCM(key), context


def encrypt(plaintext: bytes, sender: UnlockedKeys, recipient_public: bytes) -> bytes:
    """Encrypt to the recipient's public key, sign as sender, return envelope bytes."""
    if not plaintext:
        raise CryptoError("Message is empty.")
    recipient_id, recipient_x = _public_key(recipient_public, "x25519_pub")
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_x))
    aead, context = _aead_key(shared, sender.user_id, recipient_id)
    nonce = os.urandom(NONCE_LENGTH_BYTES)
    unsigned = EncryptionEnvelope(
        version=VERSION,
        sender_id=sender.user_id,
        recipient_id=recipient_id,
        algorithms=ALGORITHMS,
        ephemeral_public_key=ephemeral.public_key().public_bytes(
            ser.Encoding.Raw, ser.PublicFormat.Raw
        ),
        kem_ciphertext=b"",
        aes_gcm_nonce=nonce,
        encrypted_payload=aead.encrypt(nonce, plaintext, context),
        signature=b"",
    )
    signed = dataclasses.replace(
        unsigned, signature=sender.ed25519.sign(unsigned.authenticated_bytes())
    )
    return signed.to_bytes()


def verify_and_decrypt(
    envelope_bytes: bytes, recipient: UnlockedKeys, sender_public: bytes
) -> bytes:
    """Verify the sender's signature, then decrypt. Raises CryptoError on failure."""
    try:
        env = EncryptionEnvelope.from_bytes(envelope_bytes)
    except ValueError as exc:
        raise CryptoError(
            f"Envelope unreadable (image modified?): {exc}", tampered=True
        ) from exc
    if env.algorithms != ALGORITHMS:
        raise CryptoError("Unsupported algorithms in envelope.")
    if env.recipient_id != recipient.user_id:
        raise CryptoError(
            f"This talk is addressed to '{env.recipient_id}', "
            f"not '{recipient.user_id}'."
        )
    sender_id, sender_ed = _public_key(sender_public, "ed25519_pub")
    if env.sender_id != sender_id:
        raise CryptoError(f"This talk is from '{env.sender_id}', not '{sender_id}'.")
    try:
        Ed25519PublicKey.from_public_bytes(sender_ed).verify(
            env.signature, env.authenticated_bytes()
        )
    except InvalidSignature as exc:
        raise CryptoError(
            "Signature invalid: the talk was modified or not signed by this sender.",
            tampered=True,
        ) from exc
    shared = recipient.x25519.exchange(
        X25519PublicKey.from_public_bytes(env.ephemeral_public_key)
    )
    aead, context = _aead_key(shared, env.sender_id, env.recipient_id)
    try:
        return aead.decrypt(env.aes_gcm_nonce, env.encrypted_payload, context)
    except InvalidTag as exc:
        raise CryptoError(
            "Decryption failed: wrong key or payload tampered.", tampered=True
        ) from exc
