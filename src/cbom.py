"""CBOM (Cryptographic Bill of Materials) for one protected message.

An ingredients label for a message: which algorithms protected it, under which
standard, whether each resists a quantum attacker, and the resulting profile.

`pqc_ready` is COMPUTED from the algorithms actually used, never a constant. A CBOM tool
that reported the same score for every configuration was criticised in arXiv 2609.07849
(see docs/literature_survey.md section 4).

Takes plain algorithm strings, so it works with any envelope that carries them
(`env.algorithms.key_establishment / .encryption / .signature`).
"""

from datetime import UTC, datetime

# name prefix -> (standard, quantum status)
KNOWN = {
    "X25519": ("RFC 7748", "broken by Shor's algorithm"),
    "ML-KEM": ("NIST FIPS 203", "resists known quantum attacks"),
    "AES-256-GCM": ("NIST SP 800-38D", "resists (Grover halves strength to 128-bit)"),
    "ML-DSA": ("NIST FIPS 204", "resists known quantum attacks"),
    "Ed25519": ("RFC 8032", "broken by Shor's algorithm"),
}


def _entry(role: str, name: str) -> dict:
    for prefix, (standard, status) in KNOWN.items():
        if name.startswith(prefix):
            return {"role": role, "name": name, "standard": standard, "quantum_status": status}
    return {"role": role, "name": name, "standard": "unknown", "quantum_status": "unknown"}


def profile_of(key_establishment: str) -> str:
    parts = key_establishment.split("+")
    has_pqc = any(p.startswith("ML-KEM") for p in parts)
    has_classical = any(p.startswith("X25519") for p in parts)
    if has_pqc and has_classical:
        return "Hybrid"
    return "PQC-only" if has_pqc else "Classical"


def build_cbom(key_establishment: str, encryption: str, signature: str, now: datetime | None = None) -> dict:
    """Return the CBOM as a JSON-ready dict."""
    algorithms = [_entry("key_establishment", p) for p in key_establishment.split("+")]
    algorithms += [_entry("encryption", encryption), _entry("signature", signature)]
    profile = profile_of(key_establishment)
    # Ready only if the key exchange has a PQC part AND the signature is post-quantum.
    pqc_ready = profile != "Classical" and signature.startswith("ML-DSA")
    return {
        "cbom_version": "1",
        "timestamp": (now or datetime.now(UTC)).isoformat(),
        "profile": profile,
        "pqc_ready": pqc_ready,
        "algorithms": algorithms,
    }
