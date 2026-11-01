"""CipherCanvas Streamlit app.

Shows which pipeline stages are real and which are still placeholders, so the
demo never implies cryptography that is not running.
"""

import pandas as pd
import streamlit as st

from crypto.envelope import EncryptionEnvelope
from src.media import MediaError, embed, extract

st.set_page_config(page_title="CipherCanvas", layout="wide")
st.title("🔐 CipherCanvas — Post-Quantum Media Vault")

# Status of every stage in the Alice -> Bob pipeline. Update as modules land.
PIPELINE = [
    ("1. HNDL risk advisor", "⏳ stub", "Inputs collected, no recommendation yet."),
    ("2. Hybrid key setup (X25519 + ML-KEM)", "⏳ not built", "Will produce ephemeral_public_key + kem_ciphertext."),
    ("3. Key mixing (HKDF)", "⏳ not built", "Will merge both secrets into one AES key."),
    ("4. Encryption (AES-256-GCM)", "⏳ not built", "Will produce aes_gcm_nonce + encrypted_payload."),
    ("5. Signature (ML-DSA)", "⏳ not built", "Will sign the envelope fields."),
    ("6. Envelope format", "✅ ready", "crypto/envelope.py: pack, parse, signed-bytes layout."),
    ("7. PNG LSB embed / extract", "✅ ready", "src/media.py: hides bytes in pixel low bits."),
    ("8. CBOM", "⏳ not built", "Will list algorithms, profile, timestamp, pqc_ready."),
    ("9. Qiskit lab", "⏳ stub", "Counts below are hard-coded, not simulated."),
]

# Plain-language meaning of each envelope field (see crypto/envelope.py).
ENVELOPE_FIELDS = {
    "version": "Format edition; only 1.0 is accepted.",
    "sender_id": "Who sent it (From).",
    "recipient_id": "Who can open it (To).",
    "algorithms": "Which key setup, cipher and signature were used. Signed, so it cannot be silently downgraded.",
    "ephemeral_public_key": "Alice's one-time X25519 public key (classical half of the hybrid lock).",
    "kem_ciphertext": "ML-KEM output (post-quantum half). Empty for classical-only.",
    "aes_gcm_nonce": "12-byte one-time number; never reused with the same key.",
    "encrypted_payload": "The message, AES-GCM encrypted, with its tamper tag.",
    "signature": "Sender's signature over every field above, length-prefixed so field boundaries cannot shift.",
}

with st.sidebar:
    st.header("Pipeline status")
    st.caption("What actually runs in this build.")
    for stage, status, note in PIPELINE:
        st.markdown(f"**{stage}** — {status}  \n<small>{note}</small>", unsafe_allow_html=True)
    with st.expander("Envelope fields explained"):
        for name, meaning in ENVELOPE_FIELDS.items():
            st.markdown(f"- `{name}`: {meaning}")


# ------------------------------------------------------------------
# Placeholder backends — replace with real implementations
# ------------------------------------------------------------------
def protect_png(png_bytes: bytes, message: str, sensitivity: str, retention: int, mode: str) -> bytes:
    """Embed the message in a PNG via LSB.

    TODO(Melvin's envelope): the payload is currently PLAINTEXT, unsigned.
    """
    return embed(png_bytes, message.encode("utf-8"))


def extract_and_verify(png_bytes: bytes) -> dict:
    """Extract the hidden bytes and parse them as an envelope if possible.

    Signature verification and decryption are not implemented yet, so an
    envelope's payload is shown as sizes only, never as decrypted text.
    """
    raw = extract(png_bytes)
    try:
        envelope = EncryptionEnvelope.from_bytes(raw)
    except ValueError:
        envelope = None
    return {
        "signature_valid": None,  # None = not checked (no crypto yet)
        "envelope": envelope,
        "message": None if envelope else raw.decode("utf-8", errors="replace"),
        "tamper_detected": None,
    }


def envelope_table(env: EncryptionEnvelope) -> pd.DataFrame:
    """One row per envelope field: what it holds and what it means."""
    alg = env.algorithms
    values = {
        "version": env.version,
        "sender_id": env.sender_id,
        "recipient_id": env.recipient_id,
        "algorithms": f"{alg.key_establishment} | {alg.encryption} | {alg.signature}",
        "ephemeral_public_key": f"{len(env.ephemeral_public_key)} bytes",
        "kem_ciphertext": f"{len(env.kem_ciphertext)} bytes",
        "aes_gcm_nonce": f"{len(env.aes_gcm_nonce)} bytes",
        "encrypted_payload": f"{len(env.encrypted_payload)} bytes",
        "signature": f"{len(env.signature)} bytes",
    }
    return pd.DataFrame(
        [(k, v, ENVELOPE_FIELDS[k]) for k, v in values.items()],
        columns=["Field", "Value", "Meaning"],
    )


def run_circuit(circuit_type: str) -> dict:
    """Run a Qiskit circuit. (STUB)"""
    counts = {"00": 512, "11": 512} if circuit_type == "entanglement" else {"0": 524, "1": 500}
    return {"counts": counts, "shots": 1024}


# ------------------------------------------------------------------

tab_create, tab_unlock, tab_quantum, tab_lab = st.tabs(
    [
        "1️⃣ Create Cipher Vault",
        "2️⃣ Unlock Cipher Vault",
        "3️⃣ Quantum Risk & Benchmarks",
        "4️⃣ Qiskit Lab",
    ]
)

# ==================================================================
# TAB 1 — Create Cipher Vault
# ==================================================================
with tab_create:
    st.subheader("Create Cipher Vault")

    uploaded = st.file_uploader("Upload PNG", type=["png"], key="create_png")

    message = st.text_area("Enter hidden message", placeholder="Top-secret payload…")
    col1, col2 = st.columns(2)
    with col1:
        sensitivity = st.select_slider("Sensitivity", options=["Low", "Medium", "High", "Critical"], value="High")
    with col2:
        retention = st.slider("Retention (days)", min_value=1, max_value=365, value=30)

    mode = st.radio(
        "Recipient mode",
        ["Single recipient", "Multi-recipient (group)", "Broadcast (public)"],
        horizontal=True,
    )

    if st.button("🛡️ Protect & Embed", type="primary"):
        if uploaded is None or not message:
            st.warning("Upload a PNG and enter a message first.")
        else:
            try:
                protected_bytes = protect_png(uploaded.getvalue(), message, sensitivity, retention, mode)
            except MediaError as exc:
                st.error(f"❌ {exc}")
                st.stop()
            st.warning(
                "Message embedded as **plaintext** (no encryption yet — "
                "waiting on the crypto envelope). Do not use for real secrets."
            )
            st.download_button(
                "⬇️ Download protected image",
                data=protected_bytes,
                file_name="protected_cipher_vault.png",
                mime="image/png",
            )

# ==================================================================
# TAB 2 — Unlock Cipher Vault
# ==================================================================
with tab_unlock:
    st.subheader("Unlock Cipher Vault")

    protected = st.file_uploader("Upload protected image", type=["png"], key="unlock_png")

    if st.button("🔎 Extract & Verify"):
        if protected is None:
            st.warning("Upload a protected image first.")
        else:
            try:
                result = extract_and_verify(protected.getvalue())
            except MediaError as exc:
                st.error(f"❌ {exc}")
                st.stop()

            if result["signature_valid"] is None:
                st.info("ℹ️ Signature and tamper checks not available yet.")
            elif result["signature_valid"]:
                st.success("✅ Signature valid")
            else:
                st.error("❌ Signature invalid")

            if result["tamper_detected"]:
                st.error("🚨 Tamper detected — image has been modified!")

            if result["envelope"] is not None:
                st.success("📦 Found an encryption envelope (format v1.0).")
                st.dataframe(envelope_table(result["envelope"]), width="stretch", hide_index=True)
                st.caption("Payload not decrypted: verification and decryption are not built yet.")
            else:
                st.warning("Not an envelope: this image holds a plaintext payload (pre-crypto build).")
                with st.expander("🔓 Extracted plaintext", expanded=True):
                    st.code(result["message"], language="text")

# ==================================================================
# TAB 3 — Quantum Risk & Benchmarks
# ==================================================================
with tab_quantum:
    st.subheader("Quantum Risk & Benchmarks")

    with st.expander("What is HNDL?", expanded=True):
        st.markdown(
            "**HNDL (Harvest Now, Decrypt Later)** is a threat, not a scheme: attackers "
            "record encrypted data today and decrypt it once a large quantum computer "
            "can break RSA/ECC. Data that must stay secret for years is at risk now. "
            "CipherCanvas responds with **hybrid** protection: X25519 + ML-KEM key setup, "
            "AES-256-GCM encryption and an ML-DSA signature."
        )

    st.warning(
        "⚠️ The timing and size figures below are **illustrative placeholders, not "
        "measurements**. Real Classical vs Hybrid benchmarks replace them once the "
        "crypto engine runs."
    )

    # Classical vs Hybrid comparison
    st.markdown("### Classical vs Hybrid comparison")
    compare_df = pd.DataFrame(
        {
            "Metric": ["Key gen", "Encrypt", "Decrypt", "Sign/Verify"],
            "Classical (ms)": [2.1, 0.8, 0.6, 1.2],
            "Hybrid-PQC (ms)": [5.4, 3.1, 2.9, 4.7],
        }
    )
    st.dataframe(compare_df, width="stretch")
    st.bar_chart(compare_df.set_index("Metric"))

    # Key / ciphertext / signature sizes
    st.markdown("### Key, ciphertext, and signature sizes")
    sizes_df = pd.DataFrame(
        {
            "Artifact": ["Public key", "Private key", "Ciphertext", "Signature"],
            "Size (bytes)": [1184, 2400, 1088, 2420],
        }
    )
    st.dataframe(sizes_df, width="stretch")

    # Latency charts
    st.markdown("### Latency charts (ms)")
    lat_df = pd.DataFrame(
        {
            "Operation": ["Key gen", "Encrypt", "Decrypt", "Sign"],
            "CPU": [5.4, 3.1, 2.9, 4.7],
            "GPU": [2.0, 1.2, 1.1, 1.8],
        }
    )
    st.bar_chart(lat_df.set_index("Operation"))

    st.caption(
        "Size reference: 1,184 B public key, 2,400 B private key and 1,088 B ciphertext "
        "are the published ML-KEM-768 sizes (FIPS 203); 2,420 B is the published "
        "ML-DSA-44 signature size (FIPS 204). Our final parameter sets are not chosen yet."
    )

# ==================================================================
# TAB 4 — Qiskit Lab
# ==================================================================
with tab_lab:
    st.subheader("Qiskit Lab")

    circuit_type = st.radio(
        "Choose a circuit",
        ["Superposition (H)", "Entanglement (CNOT)"],
        horizontal=True,
    )

    st.warning("⚠️ Stub: counts are hard-coded, not simulated. The Aer order-finding lab replaces this.")

    if st.button("▶️ Run circuit", type="primary"):
        result = run_circuit(circuit_type.lower().split(" ")[0].split("(")[0] or "superposition")

        counts = result["counts"]
        st.markdown("### Measurement counts")
        st.bar_chart(pd.DataFrame({"Count": counts}))

        if circuit_type.startswith("Entanglement"):
            st.markdown(
                """
                **Why it matters:** two qubits are entangled — measuring one instantly
                correlates with the other. Quantum computers can hold exponentially many
                correlated states, which is what breaks RSA/ECC via Shor's algorithm.
                """
            )
        else:
            st.markdown(
                """
                **Why it matters:** a Hadamard gate puts a qubit in a superposition
                of |0⟩ and |1⟩. This parallel state exploration is why quantum
                attacks are fast — and why we need **PQC** (post-quantum cryptography).
                """
            )

        st.info(
            "💡 **Why PQC matters:** Shor's algorithm on a large-enough quantum computer "
            "can factor RSA keys and break ECC in polynomial time. HNDL uses "
            "lattice-based primitives that resist both classical and quantum attacks."
        )
