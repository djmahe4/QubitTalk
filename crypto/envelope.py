"""Shared Encryption Envelope schema for CipherCanvas.

Standards: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), RFC 7748 (X25519), RFC 8439 / SP 800-38D.
"""
from __future__ import annotations

import base64
import json
from dataclasses import asdict, dataclass
from typing import Any, Dict


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
        """Data that the sender signs to bind identity, algorithms, and ciphertext together."""
        return (
            f"{self.version}|{self.sender_id}|{self.recipient_id}|"
            f"{self.algorithms.key_establishment}|{self.algorithms.encryption}|{self.algorithms.signature}|"
        ).encode("utf-8") + self.ephemeral_public_key + self.kem_ciphertext + self.aes_gcm_nonce + self.encrypted_payload

    def to_bytes(self) -> bytes:
        data: Dict[str, Any] = {
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
        data = json.loads(raw.decode("utf-8"))
        alg = EnvelopeAlgorithms(**data["algorithms"])
        return cls(
            version=data["version"],
            sender_id=data["sender_id"],
            recipient_id=data["recipient_id"],
            algorithms=alg,
            ephemeral_public_key=base64.b64decode(data["ephemeral_public_key"]),
            kem_ciphertext=base64.b64decode(data["kem_ciphertext"]),
            aes_gcm_nonce=base64.b64decode(data["aes_gcm_nonce"]),
            encrypted_payload=base64.b64decode(data["encrypted_payload"]),
            signature=base64.b64decode(data["signature"]),
        )
