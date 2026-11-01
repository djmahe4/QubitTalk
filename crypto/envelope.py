"""Shared Encryption Envelope schema for CipherCanvas.

Standards: NIST FIPS 203 (ML-KEM), NIST FIPS 204 (ML-DSA), RFC 7748 (X25519), NIST SP 800-38D (AES-GCM).
"""
from __future__ import annotations

import base64
import binascii
import json
from dataclasses import asdict, dataclass
from typing import Any

SUPPORTED_VERSIONS = {"1.0"}
NONCE_LENGTH_BYTES = 12


def _text(value: Any, field: str) -> str:
    """Return `value` if it is a string; never coerce, so numbers/lists/null are rejected."""
    if not isinstance(value, str):
        raise TypeError(f"Envelope field '{field}' must be a string, got {type(value).__name__}")
    return value


@dataclass(frozen=True)
class EnvelopeAlgorithms:
    key_establishment: str  # e.g., "X25519+ML-KEM-768" or "X25519"
    encryption: str         # e.g., "AES-256-GCM"
    signature: str          # e.g., "ML-DSA-65" or "Ed25519"


@dataclass(frozen=True)
class EncryptionEnvelope:
    version: str
    sender_id: str
    recipient_id: str
    algorithms: EnvelopeAlgorithms
    ephemeral_public_key: bytes  # Classical ephemeral public key (e.g. X25519)
    kem_ciphertext: bytes        # PQC ciphertext (empty b"" if classical-only)
    aes_gcm_nonce: bytes         # 12-byte standard GCM nonce
    encrypted_payload: bytes     # AES-GCM ciphertext + tag
    signature: bytes             # Sender signature over authenticated envelope fields

    def authenticated_bytes(self) -> bytes:
        """Canonical length-prefixed bytes for sender signature verification.

        Length-prefixing every field prevents boundary shifting and canonicalization attacks.
        """
        fields = [
            self.version.encode("utf-8"),
            self.sender_id.encode("utf-8"),
            self.recipient_id.encode("utf-8"),
            self.algorithms.key_establishment.encode("utf-8"),
            self.algorithms.encryption.encode("utf-8"),
            self.algorithms.signature.encode("utf-8"),
            self.ephemeral_public_key,
            self.kem_ciphertext,
            self.aes_gcm_nonce,
            self.encrypted_payload,
        ]
        return b"".join(len(f).to_bytes(4, "big") + f for f in fields)

    def to_bytes(self) -> bytes:
        data: dict[str, Any] = {
            "version": self.version,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "algorithms": asdict(self.algorithms),
            "ephemeral_public_key": base64.b64encode(self.ephemeral_public_key).decode("ascii"),
            "kem_ciphertext": base64.b64encode(self.kem_ciphertext).decode("ascii"),
            "aes_gcm_nonce": base64.b64encode(self.aes_gcm_nonce).decode("ascii"),
            "encrypted_payload": base64.b64encode(self.encrypted_payload).decode("ascii"),
            "signature": base64.b64encode(self.signature).decode("ascii"),
        }
        return json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> EncryptionEnvelope:
        try:
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise TypeError("Envelope JSON must be an object.")

            version = data["version"]
            if version not in SUPPORTED_VERSIONS:
                raise ValueError(f"Unsupported envelope version: {version}")

            alg_data = data["algorithms"]
            alg = EnvelopeAlgorithms(
                key_establishment=_text(alg_data["key_establishment"], "key_establishment"),
                encryption=_text(alg_data["encryption"], "encryption"),
                signature=_text(alg_data["signature"], "signature"),
            )

            ephemeral_public_key = base64.b64decode(data["ephemeral_public_key"], validate=True)
            kem_ciphertext = base64.b64decode(data["kem_ciphertext"], validate=True)
            aes_gcm_nonce = base64.b64decode(data["aes_gcm_nonce"], validate=True)
            if len(aes_gcm_nonce) != NONCE_LENGTH_BYTES:
                raise ValueError(f"Nonce must be {NONCE_LENGTH_BYTES} bytes, got {len(aes_gcm_nonce)}")

            encrypted_payload = base64.b64decode(data["encrypted_payload"], validate=True)
            signature = base64.b64decode(data["signature"], validate=True)

            return cls(
                version=version,
                sender_id=_text(data["sender_id"], "sender_id"),
                recipient_id=_text(data["recipient_id"], "recipient_id"),
                algorithms=alg,
                ephemeral_public_key=ephemeral_public_key,
                kem_ciphertext=kem_ciphertext,
                aes_gcm_nonce=aes_gcm_nonce,
                encrypted_payload=encrypted_payload,
                signature=signature,
            )
        except (KeyError, TypeError, json.JSONDecodeError, binascii.Error, UnicodeDecodeError) as exc:
            raise ValueError(f"Malformed encryption envelope: {exc}") from exc
