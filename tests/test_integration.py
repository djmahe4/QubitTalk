"""Integration: an envelope (PR #4) survives a round trip through the PNG vault (PR #1).

Field values are placeholders: this checks the media <-> envelope interface, not cryptography.
"""

import io

import pytest
from PIL import Image

from crypto.envelope import EncryptionEnvelope, EnvelopeAlgorithms
from src.media import embed, extract


def make_envelope() -> EncryptionEnvelope:
    return EncryptionEnvelope(
        version="1.0",
        sender_id="alice",
        recipient_id="bob",
        algorithms=EnvelopeAlgorithms("X25519+ML-KEM-768", "AES-256-GCM", "ML-DSA-65"),
        ephemeral_public_key=b"\x01" * 32,
        kem_ciphertext=b"\x02" * 64,
        aes_gcm_nonce=b"\x03" * 12,
        encrypted_payload=b"\x04" * 40,
        signature=b"\x05" * 64,
    )


def make_png(size=(64, 64)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, (10, 20, 30)).save(buf, format="PNG")
    return buf.getvalue()


def test_envelope_round_trips_through_png():
    env = make_envelope()
    recovered = EncryptionEnvelope.from_bytes(extract(embed(make_png(), env.to_bytes())))
    assert recovered == env
    assert recovered.authenticated_bytes() == env.authenticated_bytes()


def test_plaintext_payload_is_not_an_envelope():
    with pytest.raises(ValueError):
        EncryptionEnvelope.from_bytes(extract(embed(make_png(), b"hello")))
