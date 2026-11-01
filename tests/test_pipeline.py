"""End-to-end: Alice encrypts and hides a message in a PNG; Bob extracts, verifies, decrypts.

Covers the tamper-lab story at the image level: changing pixels that carry the hidden
envelope must make Bob's check fail, while pixels beyond the payload do not matter.
"""

import io

import numpy as np
import pytest
from PIL import Image

from crypto.hybrid import CryptoError, encrypt, verify_and_decrypt
from crypto.keys import generate, unlock
from src.media import HEADER_BYTES, embed, extract

MESSAGE = b"Keep this secret for five years."


def identity(name: str):
    private, public = generate(name, "correct horse")
    return unlock(private, "correct horse"), public


def cover_png(size=(96, 96)) -> bytes:
    arr = np.random.default_rng(7).integers(0, 256, (*size, 3), dtype=np.uint8)
    out = io.BytesIO()
    Image.fromarray(arr, "RGB").save(out, format="PNG")
    return out.getvalue()


def flip_lsb(png: bytes, carrier_index: int) -> bytes:
    """Flip the lowest bit of one colour channel byte, as an attacker editing the image would."""
    arr = np.array(Image.open(io.BytesIO(png)).convert("RGB"))
    flat = arr.reshape(-1)
    flat[carrier_index] ^= 1
    out = io.BytesIO()
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(out, format="PNG")
    return out.getvalue()


@pytest.fixture(scope="module")
def vault():
    alice, alice_pub = identity("alice")
    bob, bob_pub = identity("bob")
    envelope = encrypt(MESSAGE, alice, bob_pub)
    return bob, alice_pub, envelope, embed(cover_png(), envelope)


def test_alice_to_bob_through_png(vault):
    bob, alice_pub, _, stego = vault
    assert verify_and_decrypt(extract(stego), bob, alice_pub) == MESSAGE


def test_edited_payload_pixel_is_detected(vault):
    bob, alice_pub, envelope, stego = vault
    # Pick a carrier bit inside the payload, past the 4-byte length header.
    middle_bit = HEADER_BYTES * 8 + (len(envelope) * 8) // 2
    with pytest.raises(CryptoError):
        verify_and_decrypt(extract(flip_lsb(stego, middle_bit)), bob, alice_pub)


def test_pixel_beyond_payload_does_not_matter(vault):
    bob, alice_pub, envelope, stego = vault
    beyond = (HEADER_BYTES + len(envelope)) * 8 + 5
    assert verify_and_decrypt(extract(flip_lsb(stego, beyond)), bob, alice_pub) == MESSAGE
