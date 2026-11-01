import unittest
from crypto.envelope import EncryptionEnvelope, EnvelopeAlgorithms


def sample_envelope() -> EncryptionEnvelope:
    return EncryptionEnvelope(
        version="1.0",
        sender_id="alice",
        recipient_id="bob",
        algorithms=EnvelopeAlgorithms(
            key_establishment="X25519+ML-KEM-768",
            encryption="AES-256-GCM",
            signature="ML-DSA-65",
        ),
        ephemeral_public_key=b"fake-classical-ephemeral-key",
        kem_ciphertext=b"fake-kem-ciphertext-768",
        aes_gcm_nonce=b"\x01" * 12,
        encrypted_payload=b"encrypted-vault-payload-with-tag",
        signature=b"test-sender-signature-ml-dsa",
    )


class TestEnvelope(unittest.TestCase):
    def test_envelope_roundtrip_serialization(self):
        original = sample_envelope()
        raw = original.to_bytes()
        restored = EncryptionEnvelope.from_bytes(raw)
        self.assertEqual(restored, original)

    def test_authenticated_bytes_tamper_detection(self):
        env1 = sample_envelope()
        env2 = EncryptionEnvelope(
            version=env1.version,
            sender_id=env1.sender_id,
            recipient_id=env1.recipient_id,
            algorithms=env1.algorithms,
            ephemeral_public_key=env1.ephemeral_public_key,
            kem_ciphertext=env1.kem_ciphertext,
            aes_gcm_nonce=env1.aes_gcm_nonce,
            encrypted_payload=b"tampered-vault-payload",
            signature=env1.signature,
        )
        self.assertNotEqual(env1.authenticated_bytes(), env2.authenticated_bytes())

    def test_authenticated_bytes_no_boundary_ambiguity(self):
        """Verify length-prefixing prevents boundary shifting between adjacent fields."""
        env_normal = sample_envelope()

        # Shift a character from recipient_id to sender_id ("aliceb", "ob")
        env_shifted = EncryptionEnvelope(
            version=env_normal.version,
            sender_id="aliceb",
            recipient_id="ob",
            algorithms=env_normal.algorithms,
            ephemeral_public_key=env_normal.ephemeral_public_key,
            kem_ciphertext=env_normal.kem_ciphertext,
            aes_gcm_nonce=env_normal.aes_gcm_nonce,
            encrypted_payload=env_normal.encrypted_payload,
            signature=env_normal.signature,
        )
        self.assertNotEqual(env_normal.authenticated_bytes(), env_shifted.authenticated_bytes())


if __name__ == "__main__":
    unittest.main()