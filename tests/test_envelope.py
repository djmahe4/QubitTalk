import pytest

from crypto.envelope import EncryptionEnvelope, EnvelopeAlgorithms


def make_envelope(**overrides):
    fields = dict(
        version="1",
        sender_id="alice",
        recipient_id="bob",
        algorithms=EnvelopeAlgorithms("X25519", "AES-256-GCM", "Ed25519"),
        ephemeral_public_key=b"\x01" * 32,
        kem_ciphertext=b"",
        aes_gcm_nonce=b"\x02" * 12,
        encrypted_payload=b"ciphertext+tag",
        signature=b"sig",
    )
    fields.update(overrides)
    return EncryptionEnvelope(**fields)


def test_round_trip():
    env = make_envelope()
    assert EncryptionEnvelope.from_bytes(env.to_bytes()) == env


def test_authenticated_bytes_cover_metadata():
    assert make_envelope().authenticated_bytes() != make_envelope(recipient_id="eve").authenticated_bytes()


def test_malformed_input_rejected():
    with pytest.raises(ValueError):
        EncryptionEnvelope.from_bytes(b"not json")
