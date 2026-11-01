from datetime import UTC, datetime

from src.cbom import build_cbom

HYBRID = ("X25519+ML-KEM-768", "AES-256-GCM", "ML-DSA-65")
CLASSICAL = ("X25519", "AES-256-GCM", "Ed25519")


def test_hybrid_message_is_pqc_ready():
    c = build_cbom(*HYBRID)
    assert (c["profile"], c["pqc_ready"]) == ("Hybrid", True)
    assert [a["name"] for a in c["algorithms"]] == ["X25519", "ML-KEM-768", "AES-256-GCM", "ML-DSA-65"]


def test_pqc_ready_is_computed_not_constant():
    # The failure mode in arXiv 2609.07849: same score for different configurations.
    assert build_cbom(*HYBRID)["pqc_ready"] != build_cbom(*CLASSICAL)["pqc_ready"]


def test_classical_profile_and_shor_status():
    c = build_cbom(*CLASSICAL)
    assert (c["profile"], c["pqc_ready"]) == ("Classical", False)
    assert "Shor" in c["algorithms"][0]["quantum_status"]


def test_hybrid_kex_with_classical_signature_is_not_ready():
    assert build_cbom("X25519+ML-KEM-768", "AES-256-GCM", "Ed25519")["pqc_ready"] is False


def test_pqc_only_profile():
    assert build_cbom("ML-KEM-768", "AES-256-GCM", "ML-DSA-65")["profile"] == "PQC-only"


def test_unknown_algorithm_is_marked_unknown_not_ready():
    c = build_cbom("FooKEM", "AES-256-GCM", "FooSig")
    assert c["algorithms"][0]["quantum_status"] == "unknown" and c["pqc_ready"] is False


def test_timestamp_is_injectable():
    now = datetime(2026, 11, 1, 15, 0, tzinfo=UTC)
    assert build_cbom(*HYBRID, now=now)["timestamp"].startswith("2026-11-01T15:00")
