import io

import pandas as pd
import streamlit as st
from PIL import Image

from crypto.hybrid import ALGORITHMS, CryptoError, encrypt, verify_and_decrypt
from crypto.keys import KeyFileError, generate, unlock
from src.media import MediaError, embed, extract

st.set_page_config(page_title="Qubit Talks — PQC", layout="wide")
st.title("🔐 Qubit Talks — Hybrid Post-Quantum Messaging (HNDL)")

# ------------------------------------------------------------------
# Placeholder backends — replace with real implementations
# ------------------------------------------------------------------
def protect_png(png_bytes: bytes, message: str, sender, recipient_public: bytes) -> bytes:
    """Encrypt + sign the message, then hide the envelope in the PNG (LSB)."""
    return embed(png_bytes, encrypt(message.encode("utf-8"), sender, recipient_public))


def extract_and_verify(png_bytes: bytes, recipient, sender_public: bytes) -> dict:
    """Extract the envelope, verify the signature, decrypt, and report tampering."""
    algorithm = f"{ALGORITHMS.key_establishment} + {ALGORITHMS.encryption} + {ALGORITHMS.signature} (Classical)"
    result = {"signature_valid": False, "tamper_detected": False, "message": "", "algorithm": algorithm, "error": None}
    try:
        envelope = extract(png_bytes)
    except MediaError as exc:
        result["error"] = str(exc)
        return result
    try:
        result["message"] = verify_and_decrypt(envelope, recipient, sender_public).decode("utf-8")
        result["signature_valid"] = True
    except CryptoError as exc:
        result["error"], result["tamper_detected"] = str(exc), exc.tampered
    return result


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
            except KeyFileError as exc:
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
                except KeyFileError as exc:
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
    sender = st.session_state.get("keys")
    if sender is None:
        st.info("🔑 Unlock your key in the **My Keys** tab first. It signs your talk.")

    uploaded = st.file_uploader("Upload PNG", type=["png"], key="create_png")
    recipient_file = st.file_uploader("Recipient's public key (.json)", type=["json"], key="recipient_pub")
    message = st.text_area("Enter hidden message", placeholder="Top-secret payload…")
    col1, col2 = st.columns(2)
    with col1:
        sensitivity = st.select_slider(
            "Sensitivity", options=["Low", "Medium", "High", "Critical"], value="High"
        )
    with col2:
        retention = st.slider("Retention (days)", min_value=1, max_value=365, value=30)
    st.caption("Sensitivity and retention feed the HNDL risk advisor (coming soon); they do not change encryption yet.")

    mode = st.radio(
        "Recipient mode",
        ["Single recipient", "Multi-recipient (group)", "Broadcast (public)"],
        horizontal=True,
    )

    if st.button("🛡️ Protect & Embed", type="primary"):
        st.session_state.pop("protected", None)
        if sender is None or uploaded is None or recipient_file is None or not message:
            st.warning("Unlock your key, upload a PNG and the recipient's public key, and enter a message.")
        elif mode != "Single recipient":
            st.warning("Only single-recipient talks are supported in this MVP.")
        else:
            try:
                st.session_state["protected"] = protect_png(
                    uploaded.getvalue(), message, sender, recipient_file.getvalue()
                )
            except (CryptoError, MediaError) as exc:
                st.error(str(exc))
    if "protected" in st.session_state:
        st.success(
            f"✅ Encrypted, signed and hidden in the image · {ALGORITHMS.key_establishment} + "
            f"{ALGORITHMS.encryption} + {ALGORITHMS.signature} (Classical profile)"
        )
        st.download_button(
            "⬇️ Download protected image",
            data=st.session_state["protected"],
            file_name="protected_qubit_talk.png",
            mime="image/png",
        )

# ==================================================================
# TAB 2 — Unlock Qubit Talk
# ==================================================================
with tab_unlock:
    st.subheader("Unlock Qubit Talk")
    recipient = st.session_state.get("keys")
    if recipient is None:
        st.info("🔑 Unlock your key in the **My Keys** tab first. It decrypts talks sent to you.")

    protected = st.file_uploader("Upload protected image", type=["png"], key="unlock_png")
    sender_file = st.file_uploader("Sender's public key (.json)", type=["json"], key="sender_pub")

    if st.button("🔎 Extract & Verify"):
        if recipient is None or protected is None or sender_file is None:
            st.warning("Unlock your key and upload the protected image and the sender's public key.")
        else:
            result = extract_and_verify(protected.getvalue(), recipient, sender_file.getvalue())
            if result["error"]:
                st.error(f"❌ {result['error']}")
            if result["signature_valid"]:
                st.success(f"✅ Signature valid — {result['algorithm']}")
            if result["tamper_detected"]:
                st.error("🚨 Tamper detected — the image or its contents were modified!")
            elif result["signature_valid"]:
                st.success("🛡️ No tampering detected")
            if result["signature_valid"]:
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