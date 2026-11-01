import json
import unittest

from crypto.keys import KeyFileError, classify, generate, public_summary, unlock


class TestKeys(unittest.TestCase):
    def test_generate_then_unlock_round_trip(self):
        private, public = generate("alice", "correct horse")
        keys = unlock(private, "correct horse")
        self.assertEqual(keys.user_id, "alice")
        self.assertEqual(keys.public_json(), public)
        self.assertEqual(len(keys.fingerprint()), 16)

    def test_private_file_has_no_plaintext_key_and_public_has_no_private(self):
        private, public = generate("alice", "correct horse")
        self.assertIn(
            b"ENCRYPTED PRIVATE KEY", json.loads(private)["x25519_pem"].encode()
        )
        self.assertNotIn(b"PRIVATE", public)

    def test_weak_passphrase_and_empty_name_rejected(self):
        with self.assertRaises(KeyFileError):
            generate("alice", "short")
        with self.assertRaises(KeyFileError):
            generate("  ", "correct horse")

    def test_wrong_passphrase_and_garbage_file_fail_clearly(self):
        private, _ = generate("alice", "correct horse")
        with self.assertRaises(KeyFileError):
            unlock(private, "wrong passphrase")
        with self.assertRaises(KeyFileError):
            unlock(b"not json", "correct horse")

    def test_classify_and_public_summary(self):
        private, public = generate("alice", "correct horse")
        self.assertEqual(classify(private), "private")
        self.assertEqual(classify(public), "public")
        self.assertIsNone(classify(b"hello"))
        self.assertIsNone(classify(b"[1, 2]"))
        name, fingerprint = public_summary(public)
        self.assertEqual(name, "alice")
        self.assertEqual(fingerprint, unlock(private, "correct horse").fingerprint())
        with self.assertRaises(KeyFileError):
            public_summary(b'{"id": "x", "x25519_pub": "AAAA", "ed25519_pub": "AAAA"}')


if __name__ == "__main__":
    unittest.main()
