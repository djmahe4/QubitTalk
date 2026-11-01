import io

import numpy as np
import pytest
from PIL import Image

from src.media import MediaError, capacity, embed, extract


def make_png(size=(64, 64), color=(120, 200, 40)) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", size, color).save(buf, format="PNG")
    return buf.getvalue()


def test_round_trip():
    payload = bytes(range(256)) * 3
    assert extract(embed(make_png(), payload)) == payload


def test_image_barely_changes():
    original = make_png()
    stego = embed(original, b"hello")
    a = Image.open(io.BytesIO(original)).convert("RGB")
    b = Image.open(io.BytesIO(stego)).convert("RGB")
    assert all(
        abs(x - y) <= 1 for p, q in zip(a.getdata(), b.getdata()) for x, y in zip(p, q)
    )


def test_empty_payload_rejected():
    with pytest.raises(MediaError):
        embed(make_png(), b"")


def test_oversized_payload_rejected():
    png = make_png((8, 8))
    with pytest.raises(MediaError, match="too large"):
        embed(png, b"x" * (capacity(png) + 1))
    assert extract(embed(png, b"x" * capacity(png))) == b"x" * capacity(png)


def test_extract_from_clean_image_fails():
    with pytest.raises(MediaError):
        extract(make_png())


def test_non_png_rejected():
    with pytest.raises(MediaError):
        extract(b"not an image")


def test_corrupted_length_header_rejected():
    # Embed payload then corrupt header bits to claim a length beyond image capacity
    png = make_png((8, 8))
    stego = embed(png, b"test")
    # Parse image and modify first 32 bits to a huge length
    img = Image.open(io.BytesIO(stego)).convert("RGB")
    arr = np.array(img, dtype=np.uint8)
    flat = arr.reshape(-1)
    huge_len = (1000).to_bytes(4, "big")
    bits = np.unpackbits(np.frombuffer(huge_len, dtype=np.uint8))
    flat[:32] = (flat[:32] & 0xFE) | bits
    out = io.BytesIO()
    Image.fromarray(flat.reshape(arr.shape), "RGB").save(out, format="PNG")

    with pytest.raises(MediaError):
        extract(out.getvalue())
