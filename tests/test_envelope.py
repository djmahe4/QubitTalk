import json
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
        ephemeral_public_key=b"fake-classical-ephemeral-key-32b",
        kem_ciphertext=b"fake-kem-ciphertext-768-bytes",
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
            encrypted_payload=b"tampered-vault-payload-with-tag",
            signature=env1.signature,
        )
        self.assertNotEqual(env1.authenticated_bytes(), env2.authenticated_bytes())

    def test_authenticated_bytes_text_field_boundary_shift(self):
        """Length-prefixing prevents boundary shifting between text fields."""
        env_normal = sample_envelope()
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

    def test_authenticated_bytes_binary_field_boundary_shift(self):
        """Length-prefixing prevents boundary shifting between binary fields."""
        env_normal = sample_envelope()
        # Shift one byte from ephemeral_public_key to kem_ciphertext
        env_shifted = EncryptionEnvelope(
            version=env_normal.version,
            sender_id=env_normal.sender_id,
            recipient_id=env_normal.recipient_id,
            algorithms=env_normal.algorithms,
            ephemeral_public_key=env_normal.ephemeral_public_key[:-1],
            kem_ciphertext=env_normal.ephemeral_public_key[-1:] + env_normal.kem_ciphertext,
            aes_gcm_nonce=env_normal.aes_gcm_nonce,
            encrypted_payload=env_normal.encrypted_payload,
            signature=env_normal.signature,
        )
        self.assertNotEqual(env_normal.authenticated_bytes(), env_shifted.authenticated_bytes())

    def test_base64_validation_rejects_corrupted_characters(self):
        """base64.b64decode with validate=True rejects non-base64 characters."""
        env = sample_envelope()
        raw = json.loads(env.to_bytes().decode("utf-8"))
        raw["aes_gcm_nonce"] = "!!!not-valid-base64!!!"
        with self.assertRaises(ValueError):
            EncryptionEnvelope.from_bytes(json.dumps(raw).encode("utf-8"))

    def test_missing_field_raises_value_error(self):
        env = sample_envelope()
        raw = json.loads(env.to_bytes().decode("utf-8"))
        del raw["sender_id"]
        with self.assertRaises(ValueError):
            EncryptionEnvelope.from_bytes(json.dumps(raw).encode("utf-8"))

    def test_invalid_nonce_length_rejected(self):
        env = sample_envelope()
        raw = json.loads(env.to_bytes().decode("utf-8"))
        raw["aes_gcm_nonce"] = "AAAA"  # only 3 bytes decoded
        with self.assertRaises(ValueError):
            EncryptionEnvelope.from_bytes(json.dumps(raw).encode("utf-8"))

    def test_unsupported_version_rejected(self):
        env = sample_envelope()
        raw = json.loads(env.to_bytes().decode("utf-8"))
        raw["version"] = "99.0"
        with self.assertRaises(ValueError):
            EncryptionEnvelope.from_bytes(json.dumps(raw).encode("utf-8"))

    def test_non_string_text_fields_rejected(self):
        """Numbers, lists and null must raise ValueError, not parse and fail later."""
        env = sample_envelope()
        for bad in (5, ["X25519"], None):
            for path in (
                ("algorithms", "key_establishment"),
                ("algorithms", "encryption"),
                ("algorithms", "signature"),
                ("sender_id",),
                ("recipient_id",),
            ):
                raw = json.loads(env.to_bytes().decode("utf-8"))
                target = raw
                for key in path[:-1]:
                    target = target[key]
                target[path[-1]] = bad
                with self.subTest(field=path[-1], value=bad), self.assertRaises(ValueError):
                    EncryptionEnvelope.from_bytes(json.dumps(raw).encode("utf-8"))

    def test_non_json_input_rejected(self):
        with self.assertRaises(ValueError):
            EncryptionEnvelope.from_bytes(b"not json payload")


if __name__ == "__main__":
    unittest.main()
