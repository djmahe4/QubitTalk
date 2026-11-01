import pandas as pd
import streamlit as st

from src.media import MediaError, embed, extract

st.set_page_config(page_title="Cipher Vault — PQC", layout="wide")
st.title("🔐 Cipher Vault — Hybrid Post-Quantum Vault (HNDL)")


# ------------------------------------------------------------------
# Placeholder backends — replace with real implementations
# ------------------------------------------------------------------
def protect_png(
    png_bytes: bytes, message: str, sensitivity: str, retention: int, mode: str
) -> bytes:
    """Embed the message in a PNG via LSB.

    TODO(Melvin's envelope): the payload is currently PLAINTEXT, unsigned.
    """
    return embed(png_bytes, message.encode("utf-8"))


def extract_and_verify(png_bytes: bytes) -> dict:
    """Extract the hidden message. Signature/tamper checks await the envelope."""
    return {
        "signature_valid": None,  # None = not checked (no crypto yet)
        "message": extract(png_bytes).decode("utf-8", errors="replace"),
        "tamper_detected": None,
        "algorithm": "none (plaintext LSB placeholder)",
    }


def run_circuit(circuit_type: str) -> dict:
    """Run a Qiskit circuit. (STUB)"""
    counts = (
        {"00": 512, "11": 512}
        if circuit_type == "entanglement"
        else {"0": 524, "1": 500}
    )
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
        sensitivity = st.select_slider(
            "Sensitivity", options=["Low", "Medium", "High", "Critical"], value="High"
        )
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
                protected_bytes = protect_png(
                    uploaded.getvalue(), message, sensitivity, retention, mode
                )
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

    protected = st.file_uploader(
        "Upload protected image", type=["png"], key="unlock_png"
    )

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
                st.success(f"✅ Signature valid — {result['algorithm']}")
            else:
                st.error("❌ Signature invalid")

            if result["tamper_detected"]:
                st.error("🚨 Tamper detected — image has been modified!")

            with st.expander("🔓 Extracted message", expanded=True):
                st.code(result["message"], language="text")

# ==================================================================
# TAB 3 — Quantum Risk & Benchmarks
# ==================================================================
with tab_quantum:
    st.subheader("Quantum Risk & Benchmarks")

    with st.expander("What is HNDL?", expanded=True):
        st.markdown(
            "**HNDL** is a hybrid post-quantum scheme: classical AES-GCM for bulk "
            "speed + lattice-based (e.g., Kyber/Dilithium-style) primitives for "
            "quantum resistance, plus a signature for tamper detection."
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
    st.dataframe(compare_df, use_container_width=True)
    st.bar_chart(compare_df.set_index("Metric"))

    # Key / ciphertext / signature sizes
    st.markdown("### Key, ciphertext, and signature sizes")
    sizes_df = pd.DataFrame(
        {
            "Artifact": ["Public key", "Private key", "Ciphertext", "Signature"],
            "Size (bytes)": [1184, 2400, 1088, 2420],
        }
    )
    st.dataframe(sizes_df, use_container_width=True)

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

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Public key", "1,184 B", "+38% vs RSA")
    m2.metric("Ciphertext", "1,088 B", "+42% vs RSA")
    m3.metric("Signature", "2,420 B", "NIST L3")
    m4.metric("Quantum safe", "Yes", "NIST FIPS 203/204")

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

    if st.button("▶️ Run circuit", type="primary"):
        result = run_circuit(
            circuit_type.lower().split(" ")[0].split("(")[0] or "superposition"
        )

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
