from src.bench import run_benchmark

RESULT = run_benchmark(repeats=3)


def test_has_all_operations():
    ops = [r["operation"] for r in RESULT["timings"]]
    assert ops == ["Key generation", "Sender key exchange", "Receiver key exchange", "Sign", "Verify"]


def test_timings_are_positive():
    assert all(r["classical_ms"] > 0 and r["hybrid_ms"] > 0 for r in RESULT["timings"])


def test_published_fips_sizes():
    sizes = {r["artifact"]: r for r in RESULT["sizes"]}
    assert sizes["Key-exchange ciphertext sent"]["hybrid_bytes"] == 32 + 1088  # X25519 + ML-KEM-768 (FIPS 203)
    assert sizes["Signature"]["hybrid_bytes"] == 3309  # ML-DSA-65 (FIPS 204)
    assert sizes["Signature"]["classical_bytes"] == 64  # Ed25519 (RFC 8032)


def test_hybrid_is_larger_than_classical():
    assert all(r["hybrid_bytes"] > r["classical_bytes"] for r in RESULT["sizes"])
