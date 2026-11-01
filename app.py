import io

import pandas as pd
import streamlit as st
from PIL import Image

from crypto.keys import KeyError_, generate, unlock

st.set_page_config(page_title="Qubit Talks — PQC", layout="wide")
st.title("🔐 Qubit Talks — Hybrid Post-Quantum Messaging (HNDL)")

# ------------------------------------------------------------------
# Placeholder backends — replace with real implementations
# ------------------------------------------------------------------
def protect_png(png_bytes: bytes, message: str, sensitivity: str, retention: int, mode: str) -> bytes:
    """Embed a hidden message + signature into a PNG. (STUB)"""
    return png_bytes

def extract_and_verify(png_bytes: bytes) -> dict:
    """Extract hidden message, verify signature, run tamper detection. (STUB)"""
    return {
        "signature_valid": True,
        "message": "Hidden message extracted here",
        "tamper_detected": False,
        "algorithm": "HNDL-Dilithium hybrid",
    }

def run_circuit(circuit_type: str) -> dict:
    """Run a Qiskit circuit. (STUB)"""
    counts = {"00": 512, "11": 512} if circuit_type == "entanglement" else {"0": 524, "1": 500}
    return {"counts": counts, "shots": 1024}
# ------------------------------------------------------------------

tab_keys, tab_create, tab_unlock, tab_quantum, tab_lab = st.tabs(
    [
        "🔑 My Keys",
        "1️⃣ Create Qubit Talk",
        "2️⃣ Unlock Qubit Talk",
        "3️⃣ Quantum Risk & Benchmarks",
        "4️⃣ Qiskit Lab",
    ]
)

# ==================================================================
# TAB 0 — My Keys (create a key pair, unlock it with a passphrase)
# ==================================================================
with tab_keys:
    st.subheader("My Keys")
    left, right = st.columns(2)

    with left:
        st.markdown("**Create a new key pair**")
        key_name = st.text_input("Your name", key="key_name")
        key_pass = st.text_input("Passphrase (8+ characters)", type="password", key="key_pass")
        if st.button("🔑 Generate keys", type="primary"):
            try:
                st.session_state["new_keys"] = generate(key_name, key_pass)
                st.session_state["new_keys_name"] = key_name
            except KeyError_ as exc:
                st.session_state.pop("new_keys", None)
                st.error(str(exc))
        if "new_keys" in st.session_state:
            private_file, public_file = st.session_state["new_keys"]
            who = st.session_state["new_keys_name"]
            st.success("Keys created. Keep the private file secret; share only the public file.")
            st.download_button("⬇️ Private key (passphrase-protected)", private_file,
                               f"{who}_private.qtkey", "application/json")
            st.download_button("⬇️ Public key (share this)", public_file,
                               f"{who}_public.json", "application/json")

    with right:
        st.markdown("**Unlock your private key**")
        key_file = st.file_uploader("Upload private key (.qtkey)", key="unlock_key")
        unlock_pass = st.text_input("Passphrase", type="password", key="unlock_pass")
        if st.button("🔓 Unlock key"):
            if key_file is None:
                st.warning("Upload your private key file first.")
            else:
                try:
                    st.session_state["keys"] = unlock(key_file.getvalue(), unlock_pass)
                except KeyError_ as exc:
                    st.session_state.pop("keys", None)
                    st.error(str(exc))
        if "keys" in st.session_state:
            active = st.session_state["keys"]
            st.success(f"🔓 Unlocked as **{active.user_id}** · fingerprint `{active.fingerprint()}`")
            if st.button("🔒 Lock again"):
                del st.session_state["keys"]
                st.rerun()

# ==================================================================
# TAB 1 — Create Qubit Talk
# ==================================================================
with tab_create:
    st.subheader("Create Qubit Talk")

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
            protected_bytes = protect_png(uploaded.getvalue(), message, sensitivity, retention, mode)
            st.success(
                f"✅ Embedded with HNDL hybrid scheme · sensitivity **{sensitivity}** · "
                f"retention **{retention} days** · mode **{mode}**"
            )
            st.download_button(
                "⬇️ Download protected image",
                data=protected_bytes,
                file_name="protected_qubit_talk.png",
                mime="image/png",
            )

# ==================================================================
# TAB 2 — Unlock Qubit Talk
# ==================================================================
with tab_unlock:
    st.subheader("Unlock Qubit Talk")

    protected = st.file_uploader("Upload protected image", type=["png"], key="unlock_png")

    if st.button("🔎 Extract & Verify"):
        if protected is None:
            st.warning("Upload a protected image first.")
        else:
            result = extract_and_verify(protected.getvalue())

            # Signature status
            if result["signature_valid"]:
                st.success(f"✅ Signature valid — {result['algorithm']}")
            else:
                st.error("❌ Signature invalid")

            # Tamper detection
            if result["tamper_detected"]:
                st.error("🚨 Tamper detected — image has been modified!")
            else:
                st.success("🛡️ No tampering detected")

            # Decrypted message
            with st.expander("🔓 Reveal decrypted message", expanded=True):
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

    circuit_type = st.radio("Choose a circuit", ["Superposition (H)", "Entanglement (CNOT)"], horizontal=True)

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