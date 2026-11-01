"""Measured Classical vs Hybrid cost: time and size of the real primitives.

Classical = X25519 key exchange + Ed25519 signature.
Hybrid    = X25519 + ML-KEM-768 key exchange + ML-DSA-65 signature.
These are the primitives CipherCanvas uses; AES-GCM cost is the same for both profiles
and is left out. Numbers are measured on this machine, not quoted from papers.

Sources: NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), RFC 7748 (X25519), RFC 8032 (Ed25519).
"""

from statistics import median
from time import perf_counter

from cryptography.hazmat.primitives.asymmetric import ed25519, mldsa, mlkem, x25519

MESSAGE = b"CipherCanvas benchmark message"


def _ms(fn, repeats: int) -> float:
    """Median wall time of fn() in milliseconds."""
    times = []
    for _ in range(repeats):
        start = perf_counter()
        fn()
        times.append((perf_counter() - start) * 1000)
    return median(times)


def run_benchmark(repeats: int = 30) -> dict:
    """Return {'timings': [rows], 'sizes': [rows]} comparing Classical and Hybrid."""
    peer = x25519.X25519PrivateKey.generate()
    kem_sk = mlkem.MLKEM768PrivateKey.generate()
    kem_pk = kem_sk.public_key()
    _, kem_ct = kem_pk.encapsulate()
    ed_sk = ed25519.Ed25519PrivateKey.generate()
    dsa_sk = mldsa.MLDSA65PrivateKey.generate()
    ed_sig, dsa_sig = ed_sk.sign(MESSAGE), dsa_sk.sign(MESSAGE)

    def classical_send():
        x25519.X25519PrivateKey.generate().exchange(peer.public_key())

    def hybrid_send():
        classical_send()
        kem_pk.encapsulate()

    eph_pub = x25519.X25519PrivateKey.generate().public_key()  # arrives with the message; receiver does not generate it

    def classical_open():
        peer.exchange(eph_pub)

    def hybrid_open():
        classical_open()
        kem_sk.decapsulate(kem_ct)

    pairs = [
        (
            "Key generation",
            lambda: x25519.X25519PrivateKey.generate(),
            lambda: (x25519.X25519PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()),
        ),
        ("Sender key exchange", classical_send, hybrid_send),
        ("Receiver key exchange", classical_open, hybrid_open),
        ("Sign", lambda: ed_sk.sign(MESSAGE), lambda: dsa_sk.sign(MESSAGE)),
        (
            "Verify",
            lambda: ed_sk.public_key().verify(ed_sig, MESSAGE),
            lambda: dsa_sk.public_key().verify(dsa_sig, MESSAGE),
        ),
    ]
    timings = [{"operation": n, "classical_ms": _ms(c, repeats), "hybrid_ms": _ms(h, repeats)} for n, c, h in pairs]

    x_pub = len(peer.public_key().public_bytes_raw())
    sizes = [
        {
            "artifact": "Key-exchange public key",
            "classical_bytes": x_pub,
            "hybrid_bytes": x_pub + len(kem_pk.public_bytes_raw()),
        },
        {"artifact": "Key-exchange ciphertext sent", "classical_bytes": x_pub, "hybrid_bytes": x_pub + len(kem_ct)},
        {"artifact": "Signature", "classical_bytes": len(ed_sig), "hybrid_bytes": len(dsa_sig)},
    ]
    return {"timings": timings, "sizes": sizes}
