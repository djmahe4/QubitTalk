import dataclasses
import io
import unittest

import numpy as np
from PIL import Image

from crypto.envelope import EncryptionEnvelope
from crypto.hybrid import CryptoError, encrypt, verify_and_decrypt
from crypto.keys import generate, unlock
from src.media import embed, extract


def identity(name):
    private, public = generate(name, "correct horse")
    return unlock(private, "correct horse"), public


def png(size=(64, 64)):
    arr = np.random.default_rng(1).integers(0, 256, (*size, 3), dtype=np.uint8)
    out = io.BytesIO()
    Image.fromarray(arr, "RGB").save(out, format="PNG")
    return out.getvalue()


class TestHybrid(unittest.TestCase):
    def setUp(self):
        self.alice, self.alice_pub = identity("alice")
        self.bob, self.bob_pub = identity("bob")
        self.env = encrypt(b"meet at TinkerSpace", self.alice, self.bob_pub)

    def test_round_trip(self):
        self.assertEqual(
            verify_and_decrypt(self.env, self.bob, self.alice_pub),
            b"meet at TinkerSpace",
        )

    def test_round_trip_through_png(self):
        hidden = extract(embed(png(), self.env))
        self.assertEqual(
            verify_and_decrypt(hidden, self.bob, self.alice_pub), b"meet at TinkerSpace"
        )

    def test_empty_message_rejected(self):
        with self.assertRaises(CryptoError):
            encrypt(b"", self.alice, self.bob_pub)

    def test_flipped_payload_bit_fails_signature(self):
        env = EncryptionEnvelope.from_bytes(self.env)
        bad = bytearray(env.encrypted_payload)
        bad[0] ^= 1
        tampered = dataclasses.replace(env, encrypted_payload=bytes(bad)).to_bytes()
        with self.assertRaisesRegex(CryptoError, "Signature invalid"):
            verify_and_decrypt(tampered, self.bob, self.alice_pub)

    def test_altered_recipient_metadata_fails(self):
        env = dataclasses.replace(
            EncryptionEnvelope.from_bytes(self.env), recipient_id="eve"
        )
        eve, _ = identity("eve")
        with self.assertRaisesRegex(CryptoError, "Signature invalid"):
            verify_and_decrypt(env.to_bytes(), eve, self.alice_pub)

    def test_wrong_recipient_and_wrong_sender_rejected(self):
        carol, _ = identity("carol")
        with self.assertRaisesRegex(CryptoError, "addressed to"):
            verify_and_decrypt(self.env, carol, self.alice_pub)
        with self.assertRaisesRegex(CryptoError, "from 'alice'"):
            verify_and_decrypt(self.env, self.bob, self.bob_pub)

    def test_forged_sender_key_fails_signature(self):
        _, imposter_pub = identity("alice")  # same name, different keys
        with self.assertRaisesRegex(CryptoError, "Signature invalid"):
            verify_and_decrypt(self.env, self.bob, imposter_pub)

    def test_garbage_envelope_and_bad_public_file(self):
        with self.assertRaises(CryptoError):
            verify_and_decrypt(b"junk", self.bob, self.alice_pub)
        with self.assertRaises(CryptoError):
            encrypt(b"hi", self.alice, b"not a key file")

    def test_nonce_unique_per_encryption(self):
        other = encrypt(b"meet at TinkerSpace", self.alice, self.bob_pub)
        self.assertNotEqual(
            EncryptionEnvelope.from_bytes(self.env).aes_gcm_nonce,
            EncryptionEnvelope.from_bytes(other).aes_gcm_nonce,
        )


if __name__ == "__main__":
    unittest.main()
