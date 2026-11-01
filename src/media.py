"""PNG LSB media vault: hide and recover opaque bytes in an image.

Technique: least-significant-bit (LSB) steganography. Each RGB channel byte
donates its lowest bit, so a pixel changes by at most 1/255 per channel and
the image looks unchanged. PNG is lossless, so the bits survive saving.
(LSB steganography hides data; it does not protect it. Confidentiality comes
from the encrypted envelope that callers pass in.)

Layout of the hidden stream: 4-byte big-endian payload length, then payload.
"""

import io

import numpy as np
from PIL import Image

HEADER_BYTES = 4


class MediaError(ValueError):
    """Raised for oversized payloads, bad images, or missing embedded data."""


def _load_rgb(png_bytes: bytes) -> np.ndarray:
    try:
        img = Image.open(io.BytesIO(png_bytes))
        if img.format != "PNG":
            raise MediaError("Input is not a PNG image.")
        return np.array(img.convert("RGB"), dtype=np.uint8)
    except OSError as exc:
        raise MediaError("Could not read image as PNG.") from exc


def capacity(png_bytes: bytes) -> int:
    """Max payload size in bytes this image can hold."""
    return max(_load_rgb(png_bytes).size // 8 - HEADER_BYTES, 0)


def embed(png_bytes: bytes, payload: bytes) -> bytes:
    """Return a new PNG with `payload` hidden in its pixel LSBs."""
    if not payload:
        raise MediaError("Payload is empty.")
    pixels = _load_rgb(png_bytes)
    flat = pixels.reshape(-1).copy()
    stream = len(payload).to_bytes(HEADER_BYTES, "big") + payload
    bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
    # One carrier byte per bit; an exact fill (bits.size == flat.size) is allowed.
    if bits.size > flat.size:
        raise MediaError("Payload too large for this image.")
    flat[: bits.size] = (flat[: bits.size] & 0xFE) | bits

    out = io.BytesIO()
    Image.fromarray(flat.reshape(pixels.shape), "RGB").save(out, format="PNG")
    return out.getvalue()


def extract(png_bytes: bytes) -> bytes:
    """Recover the payload hidden by `embed`."""
    flat = _load_rgb(png_bytes).reshape(-1)
    if flat.size < HEADER_BYTES * 8:
        raise MediaError("Image too small to contain a payload.")
    length = int.from_bytes(np.packbits(flat[: HEADER_BYTES * 8] & 1).tobytes(), "big")
    end = (HEADER_BYTES + length) * 8
    # Reject an empty or corrupted header before slicing, so we never return truncated bytes.
    if length == 0 or end > flat.size:
        raise MediaError("No embedded payload found.")
    return np.packbits(flat[HEADER_BYTES * 8 : end] & 1).tobytes()
