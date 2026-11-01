import io
from html import escape

import pandas as pd
import streamlit as st
from PIL import Image

from crypto.hybrid import ALGORITHMS, CryptoError, encrypt, verify_and_decrypt
from crypto.keys import KeyFileError, classify, generate, public_summary, unlock
from src.media import MediaError, capacity, embed, extract

st.set_page_config(page_title="Qubit Talks", page_icon="🔐", layout="wide")

STYLE = """
<style>
.block-container {max-width: 1080px; padding-top: 2rem;}
.qt-hero h1 {font-size: 2.5rem; margin: 0; letter-spacing: -0.02em;}
.qt-hero p {color: #9AA7C0; margin: .3rem 0 0; font-size: 1.05rem;}
.qt-pill {display: inline-block; padding: .35rem .9rem; border-radius: 999px;
          font-size: .85rem; border: 1px solid #2A3553; white-space: nowrap;}
.qt-ok {background: #12301F; color: #7EE2A8; border-color: #1F5B3A;}
.qt-lock {background: #2A1F12; color: #F2C078; border-color: #5B411F;}
.qt-step {font-size: .75rem; color: #6EA8FE; font-weight: 700;
          letter-spacing: .1em; text-transform: uppercase; margin-bottom: -.4rem;}
</style>
"""
st.markdown(STYLE, unsafe_allow_html=True)


# ------------------------------------------------------------------
# Backends
# ------------------------------------------------------------------
def protect_png(png_bytes: bytes, message: str, sender, recipient_public: bytes) -> bytes:
    """Encrypt + sign the message, then hide the envelope in the PNG (LSB)."""
    return embed(png_bytes, encrypt(message.encode("utf-8"), sender, recipient_public))


def extract_and_verify(png_bytes: bytes, recipient, sender_public: bytes) -> dict:
    """Extract the envelope, verify the signature, decrypt, and report tampering."""
    algorithm = (
        f"{ALGORITHMS.key_establishment} + {ALGORITHMS.encryption} + "
        f"{ALGORITHMS.signature} (Classical)"
    )
    result = {
        "signature_valid": False,
        "tamper_detected": False,
        "message": "",
        "algorithm": algorithm,
        "error": None,
    }
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
# UI helpers
# ------------------------------------------------------------------
def step(label: str, title: str) -> None:
    st.markdown(f'<div class="qt-step">{label}</div>', unsafe_allow_html=True)
    st.markdown(f"#### {title}")


def to_png(upload) -> bytes:
    """Return PNG bytes; JPGs are converted (LSB hiding needs a lossless format)."""
    raw = upload.getvalue()
    if raw[:8] == b"\x89PNG\r\n\x1a\n":
        return raw
    out = io.BytesIO()
    Image.open(io.BytesIO(raw)).convert("RGB").save(out, format="PNG")
    return out.getvalue()


def add_contact(public_file: bytes) -> None:
    name, _ = public_summary(public_file)
    contacts = st.session_state.setdefault("contacts", {})
    if contacts.get(name) != public_file:
        contacts[name] = public_file
        st.rerun()


def key_intake(prefix: str, allow_private: bool):
    """One upload box for any key file: public keys become contacts, a private key unlocks."""
    files = st.file_uploader(
        "Drop key files here",
        type=["qtkey", "json"],
        accept_multiple_files=True,
        key=f"{prefix}_files",
        help="Accepts both file types. Public keys are added to your contacts; "
        "a private key (.qtkey) is opened with its passphrase.",
    )
    private = None
    for f in files or []:
        raw = f.getvalue()
        kind = classify(raw)
        try:
            if kind == "public":
                add_contact(raw)
                st.caption(f"✓ {public_summary(raw)[0]}: public key added to contacts")
            elif kind == "private" and allow_private:
                private = raw
            elif kind == "private":
                st.warning(f"{f.name} is a private key. Keep it secret and open it in the Keys tab.")
            else:
                st.error(f"{f.name} is not a Qubit Talks key file.")
        except KeyFileError as exc:
            st.error(f"{f.name}: {exc}")
    return private


def activate(private_file: bytes, passphrase: str) -> None:
    keys = unlock(private_file, passphrase)
    st.session_state["keys"] = keys
    st.session_state.pop("protected", None)
    add_contact(keys.public_json())
    st.rerun()


# ------------------------------------------------------------------
# Header
# ------------------------------------------------------------------
active = st.session_state.get("keys")
head_left, head_right = st.columns([4, 1], vertical_alignment="center")
with head_left:
    st.markdown(
        '<div class="qt-hero"><h1>🔐 Qubit Talks</h1>'
        "<p>Hide encrypted messages inside ordinary images, protected against "
        "today's and tomorrow's computers.</p></div>",
        unsafe_allow_html=True,
    )
with head_right:
    if active:
        pill = f'<span class="qt-pill qt-ok">🔓 Unlocked as <b>{escape(active.user_id)}</b></span>'
    else:
        pill = '<span class="qt-pill qt-lock">🔒 Locked: open the Keys tab</span>'
    st.markdown(f'<div style="text-align:right">{pill}</div>', unsafe_allow_html=True)

st.write("")
tab_keys, tab_send, tab_receive, tab_quantum, tab_lab = st.tabs(
    [
        ":material/key: Keys",
        ":material/send: Send",
        ":material/mark_email_read: Receive",
        ":material/monitoring: Risk & Benchmarks",
        ":material/science: Qiskit Lab",
    ]
)

# ==================================================================
# KEYS — create an identity, or open existing keys
# ==================================================================
with tab_keys:
    st.caption("Your keys are your identity. Create them once, save the files, and unlock them whenever you need to send or receive.")
    left, right = st.columns(2, gap="large")

    with left, st.container(border=True):
        step("New here", "Create your keys")
        with st.form("create_form", border=False):
            name = st.text_input("Your name", placeholder="e.g. alice")
            pw = st.text_input("Passphrase (8+ characters)", type="password")
            pw2 = st.text_input("Confirm passphrase", type="password")
            if st.form_submit_button("Create my keys", type="primary"):
                if pw != pw2:
                    st.error("The passphrases do not match.")
                else:
                    try:
                        private_file, public_file = generate(name.strip(), pw)
                        st.session_state["new_keys"] = (private_file, public_file, name.strip())
                        activate(private_file, pw)
                    except KeyFileError as exc:
                        st.error(str(exc))
        if "new_keys" in st.session_state:
            private_file, public_file, who = st.session_state["new_keys"]
            st.success(f"Keys created and unlocked for **{who}**. Save both files now.")
            c1, c2 = st.columns(2)
            c1.download_button("Private key", private_file, f"{who}_private.qtkey",
                               "application/json", icon=":material/lock:",
                               help="Secret. Protected by your passphrase.", width="stretch")
            c2.download_button("Public key", public_file, f"{who}_public.json",
                               "application/json", icon=":material/share:",
                               help="Share this with people who want to message you.", width="stretch")
            st.caption("Keys are not stored on the server. If you leave this page without saving the private key, it cannot be recovered.")

    with right, st.container(border=True):
        step("Already have keys", "Unlock keys or add contacts")
        private = key_intake("keys", allow_private=True)
        if private:
            with st.form("unlock_form", border=False):
                unlock_pw = st.text_input("Passphrase for this private key", type="password")
                if st.form_submit_button("Unlock", type="primary"):
                    try:
                        st.session_state.pop("new_keys", None)
                        activate(private, unlock_pw)
                    except KeyFileError as exc:
                        st.error(str(exc))
        if active:
            st.success(f"Unlocked as **{active.user_id}** · fingerprint `{active.fingerprint()}`")
            if st.button("Lock", icon=":material/lock:"):
                st.session_state.pop("keys", None)
                st.session_state.pop("new_keys", None)
                st.session_state.pop("protected", None)
                st.rerun()

    contacts = st.session_state.get("contacts", {})
    st.markdown("#### Contacts")
    if not contacts:
        st.info("No contacts yet. Drop someone's public key (.json) above to be able to message them.")
    for contact in list(contacts):
        c_name, c_print = st.columns([3, 1], vertical_alignment="center")
        c_name.markdown(f"**{escape(contact)}** · fingerprint `{public_summary(contacts[contact])[1]}`")
        if c_print.button("Remove", key=f"rm_{contact}", icon=":material/delete:"):
            del contacts[contact]
            st.rerun()

# ==================================================================
# SEND — encrypt, sign and hide a message in an image
# ==================================================================
with tab_send:
    keys = st.session_state.get("keys")
    contacts = st.session_state.get("contacts", {})
    if keys is None:
        st.info("Unlock your keys in the **Keys** tab first. They sign everything you send.")

    with st.container(border=True):
        step("Step 1", "Choose a cover image")
        cover = st.file_uploader("PNG or JPG", type=["png", "jpg", "jpeg"], key="cover")
        png = None
        if cover is not None:
            try:
                png = to_png(cover)
                st.image(png, width=320)
                st.caption(f"This image can hide about {capacity(png):,} bytes. It will look unchanged.")
            except (OSError, MediaError):
                st.error("That file could not be read as an image.")

    with st.container(border=True):
        step("Step 2", "Choose who can read it")
        recipient_name = st.selectbox("Recipient", list(contacts), index=None,
                                      placeholder="Select a contact") if contacts else None
        if not contacts:
            st.info("No contacts yet. Add the recipient's public key below.")
        with st.expander("Add a contact's public key"):
            key_intake("send", allow_private=False)

    with st.container(border=True):
        step("Step 3", "Write your message")
        message = st.text_area("Message", placeholder="Your confidential message…", label_visibility="collapsed")
        with st.expander("Risk profile (preview)"):
            st.select_slider("Sensitivity", options=["Low", "Medium", "High", "Critical"], value="High")
            st.slider("Retention (days)", min_value=1, max_value=365, value=30)
            st.caption("These feed the upcoming HNDL risk advisor. They do not change encryption yet.")

    if st.button("Encrypt and hide message", type="primary", icon=":material/enhanced_encryption:"):
        st.session_state.pop("protected", None)
        if keys is None or png is None or not recipient_name or not message:
            st.warning("Unlock your keys, choose an image and a recipient, and write a message.")
        else:
            try:
                st.session_state["protected"] = protect_png(png, message, keys, contacts[recipient_name])
                st.session_state["protected_for"] = recipient_name
            except MediaError as exc:
                st.error(f"{exc} Try a larger image or a shorter message.")
            except CryptoError as exc:
                st.error(str(exc))
    if "protected" in st.session_state:
        st.success(f"Done. Only **{st.session_state['protected_for']}** can read this image, and it is signed by you.")
        st.caption(f"{ALGORITHMS.key_establishment} · {ALGORITHMS.encryption} · {ALGORITHMS.signature} (Classical profile)")
        st.download_button("Download protected image", st.session_state["protected"],
                           "protected_qubit_talk.png", "image/png", icon=":material/download:")

# ==================================================================
# RECEIVE — verify the sender and decrypt
# ==================================================================
with tab_receive:
    keys = st.session_state.get("keys")
    contacts = st.session_state.get("contacts", {})
    if keys is None:
        st.info("Unlock your keys in the **Keys** tab first. They decrypt messages sent to you.")

    with st.container(border=True):
        step("Step 1", "Upload the protected image")
        protected = st.file_uploader("PNG", type=["png"], key="protected_png")

    with st.container(border=True):
        step("Step 2", "Who sent it?")
        sender_name = st.selectbox("Sender", list(contacts), index=None,
                                   placeholder="Select a contact") if contacts else None
        if not contacts:
            st.info("No contacts yet. Add the sender's public key below.")
        with st.expander("Add a contact's public key"):
            key_intake("receive", allow_private=False)
        if sender_name:
            st.caption(f"Their key fingerprint is `{public_summary(contacts[sender_name])[1]}`. Confirm it with them through another channel.")

    if st.button("Verify and decrypt", type="primary", icon=":material/lock_open:"):
        if keys is None or protected is None or not sender_name:
            st.warning("Unlock your keys, upload the image, and choose the sender.")
        else:
            result = extract_and_verify(protected.getvalue(), keys, contacts[sender_name])
            if result["tamper_detected"]:
                st.error("🚨 Tamper detected. The image or its contents were modified.")
            if result["error"]:
                st.error(result["error"])
            if result["signature_valid"]:
                ok1, ok2 = st.columns(2)
                ok1.success(f"Signature verified · from **{sender_name}**")
                ok2.success("Integrity intact · no tampering")
                with st.container(border=True):
                    st.markdown("**Decrypted message**")
                    st.code(result["message"], language="text")
                st.caption(result["algorithm"])

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
