import io
from html import escape
from math import gcd

import pandas as pd
import streamlit as st
from PIL import Image

from crypto.envelope import EncryptionEnvelope
from crypto.hybrid import ALGORITHMS, CryptoError, encrypt, verify_and_decrypt
from crypto.keys import KeyFileError, classify, generate, public_summary, unlock
from crypto.password import analyze_password_strength
from src.advisor import DEFAULT_MIGRATION_YEARS, DEFAULT_THREAT_YEARS, SENSITIVITIES, advise
from src.bench import run_benchmark
from src.cbom import build_cbom
from src.media import MediaError, capacity, embed, extract
from src.qlab import find_order

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
    algorithm = f"{ALGORITHMS.key_establishment} + {ALGORITHMS.encryption} + {ALGORITHMS.signature} (Classical)"
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
        result["envelope"] = EncryptionEnvelope.from_bytes(envelope)
    except CryptoError as exc:
        result["error"], result["tamper_detected"] = str(exc), exc.tampered
    return result


def cbom_for(alg) -> dict:
    """CBOM for the algorithms that actually protected this message."""
    return build_cbom(alg.key_establishment, alg.encryption, alg.signature)


# Plain-language meaning of each envelope field (crypto/envelope.py).
ENVELOPE_FIELDS = {
    "version": "Format edition; only 1.0 is accepted.",
    "sender_id / recipient_id": "From and To. Signed, so they cannot be swapped.",
    "algorithms": "Key setup, cipher and signature used. Signed, so no silent downgrade.",
    "ephemeral_public_key": "Alice's one-time X25519 public key.",
    "kem_ciphertext": "ML-KEM output (post-quantum half). Empty in the classical profile.",
    "aes_gcm_nonce": "12-byte one-time number; never reused with a key.",
    "encrypted_payload": "The message, AES-256-GCM encrypted, plus its tamper tag.",
    "signature": "Sender's signature over every field above.",
}


def envelope_table(env: EncryptionEnvelope) -> pd.DataFrame:
    a = env.algorithms
    values = [
        env.version,
        f"{env.sender_id} → {env.recipient_id}",
        f"{a.key_establishment} · {a.encryption} · {a.signature}",
        f"{len(env.ephemeral_public_key)} bytes",
        f"{len(env.kem_ciphertext)} bytes",
        f"{len(env.aes_gcm_nonce)} bytes",
        f"{len(env.encrypted_payload)} bytes",
        f"{len(env.signature)} bytes",
    ]
    rows = zip(ENVELOPE_FIELDS, values, ENVELOPE_FIELDS.values(), strict=True)
    return pd.DataFrame(rows, columns=["Field", "This message", "Meaning"])


@st.cache_data(show_spinner="Measuring the real primitives…")
def cached_benchmark() -> dict:
    return run_benchmark()


@st.cache_data(show_spinner="Running the circuit on Qiskit Aer…")
def cached_order(a: int):
    r = find_order(a, 15)
    return r.counts, r.order, r.factors, str(r.circuit.draw(output="text", fold=-1))


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


def render_password_strength(password: str) -> None:
    """Render interactive password strength meter and quantum security metrics."""
    res = analyze_password_strength(password)
    c_status, c_bar = st.columns([1, 3], vertical_alignment="center")
    badge = (
        '<span style="display:inline-block; padding: 4px 14px; border-radius: 999px; '
        f"font-weight: 700; font-size: 0.85rem; color: #fff; "
        f'background-color: {res.color};">'
        f"{res.level.upper()} ({res.score}/100)</span>"
    )
    c_status.markdown(badge, unsafe_allow_html=True)
    c_bar.progress(res.score / 100)

    m1, m2, m3 = st.columns(3)
    m1.metric("Entropy", f"{res.entropy_bits} bits")
    m2.metric("Classical Crack Time", res.classical_crack_time)
    m3.metric("Quantum Grover Crack Time", res.quantum_crack_time)

    with st.expander("Security Breakdown & Recommendations", expanded=(res.level != "Hard")):
        for tip in res.feedback:
            st.markdown(f"- {tip}")
        if res.level == "Hard":
            st.success("🔒 High-strength passphrase: safe against both classical and quantum attacks.")
        elif res.level == "Medium":
            st.info("⚠️ Moderate strength: acceptable, but consider adding more length or symbols.")
        else:
            st.warning("🚨 Weak passphrase: vulnerable to automated brute-force attacks.")


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

PIPELINE = [
    ("HNDL risk advisor", "✅", "Mosca's inequality, assumptions shown"),
    ("Keys (X25519 + Ed25519)", "✅", "Passphrase-protected key files"),
    ("Key setup + HKDF + AES-256-GCM", "✅", "Classical profile"),
    ("Signature (Ed25519)", "✅", "Covers every envelope field"),
    ("PNG LSB embed / extract", "✅", "Hiding, not security"),
    ("CBOM", "✅", "pqc_ready computed per message"),
    ("Qiskit order-finding lab", "✅", "Real circuit on Aer, N = 15"),
    ("Benchmarks", "✅", "Measured on this machine"),
    ("ML-KEM-768 + ML-DSA-65", "⏳", "Next: hybrid PQC profile"),
]
with st.sidebar:
    st.header("What runs in this build")
    for stage, status, note in PIPELINE:
        st.markdown(f"{status} **{stage}**  \n<small>{note}</small>", unsafe_allow_html=True)
    st.caption(
        "Messages use the classical profile until the ML-KEM / ML-DSA step lands. Nothing post-quantum is claimed before then."
    )

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
    st.caption(
        "Your keys are your identity. Create them once, save the files, and unlock them whenever you need to send or receive."
    )
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
                        st.session_state["new_keys"] = (
                            private_file,
                            public_file,
                            name.strip(),
                        )
                        activate(private_file, pw)
                    except KeyFileError as exc:
                        st.error(str(exc))
        if "new_keys" in st.session_state:
            private_file, public_file, who = st.session_state["new_keys"]
            st.success(f"Keys created and unlocked for **{who}**. Save both files now.")
            c1, c2 = st.columns(2)
            c1.download_button(
                "Private key",
                private_file,
                f"{who}_private.qtkey",
                "application/json",
                icon=":material/lock:",
                help="Secret. Protected by your passphrase.",
                width="stretch",
            )
            c2.download_button(
                "Public key",
                public_file,
                f"{who}_public.json",
                "application/json",
                icon=":material/share:",
                help="Share this with people who want to message you.",
                width="stretch",
            )
            st.caption(
                "Keys are not stored on the server. If you leave this page without saving the private key, it cannot be recovered."
            )

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

    st.write("")
    with st.container(border=True):
        st.markdown("### 🛡️ Password & Passphrase Strength Analyzer")
        st.caption(
            "Analyze whether your passphrase is **Weak**, **Medium**, or **Hard**. "
            "Evaluates entropy, brute-force resistance, and speedup from "
            "Grover's quantum search algorithm."
        )
        test_pw = st.text_input(
            "Test a password or passphrase",
            type="password",
            placeholder="Type any password or passphrase here...",
            key="pw_analyzer_input",
            help="Your password is analyzed entirely locally in your browser/session. "
            "It is never stored or transmitted.",
        )
        if test_pw:
            render_password_strength(test_pw)

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
        recipient_name = (
            st.selectbox("Recipient", list(contacts), index=None, placeholder="Select a contact") if contacts else None
        )
        if not contacts:
            st.info("No contacts yet. Add the recipient's public key below.")
        with st.expander("Add a contact's public key"):
            key_intake("send", allow_private=False)

    with st.container(border=True):
        step("Step 3", "Write your message")
        message = st.text_area(
            "Message",
            placeholder="Your confidential message…",
            label_visibility="collapsed",
        )
    with st.container(border=True):
        step("Step 4", "How long must it stay secret?")
        r1, r2 = st.columns(2)
        sensitivity = r1.select_slider("Sensitivity", options=list(SENSITIVITIES), value="High")
        retention = r2.slider("Keep secret for (years)", min_value=1, max_value=30, value=5)
        advice = advise(sensitivity, retention)
        (st.warning if advice.at_risk else st.success)(f"**Recommended: {advice.profile}.** {advice.reason}")
        if advice.profile != "Classical":
            st.caption(
                "This build encrypts with the classical profile. The ML-KEM / ML-DSA upgrade is the next step; "
                "see the Risk tab for why it matters."
            )

    if st.button(
        "Encrypt and hide message",
        type="primary",
        icon=":material/enhanced_encryption:",
    ):
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
        st.caption(
            f"{ALGORITHMS.key_establishment} · {ALGORITHMS.encryption} · {ALGORITHMS.signature} (Classical profile)"
        )
        st.download_button(
            "Download protected image",
            st.session_state["protected"],
            "protected_qubit_talk.png",
            "image/png",
            icon=":material/download:",
        )
        sent = EncryptionEnvelope.from_bytes(extract(st.session_state["protected"]))
        with st.expander("What is hidden inside the image (the envelope)"):
            st.dataframe(envelope_table(sent), hide_index=True, width="stretch")
        with st.expander("CBOM: the ingredients label for this message"):
            st.json(cbom_for(sent.algorithms))

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
        sender_name = (
            st.selectbox("Sender", list(contacts), index=None, placeholder="Select a contact") if contacts else None
        )
        if not contacts:
            st.info("No contacts yet. Add the sender's public key below.")
        with st.expander("Add a contact's public key"):
            key_intake("receive", allow_private=False)
        if sender_name:
            st.caption(
                f"Their key fingerprint is `{public_summary(contacts[sender_name])[1]}`. Confirm it with them through another channel."
            )

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
                with st.expander("Envelope and CBOM"):
                    st.dataframe(envelope_table(result["envelope"]), hide_index=True, width="stretch")
                    st.json(cbom_for(result["envelope"].algorithms))

# ==================================================================
# RISK & BENCHMARKS — why this is necessary, and what it costs
# ==================================================================
with tab_quantum:
    st.subheader("Why protect against quantum computers today?")
    st.markdown(
        "**Harvest Now, Decrypt Later (HNDL)** is a threat: attackers record encrypted data today and "
        "decrypt it once a large quantum computer can break RSA and elliptic-curve keys. "
        "Data that must stay secret for years is already at risk."
    )

    with st.container(border=True):
        st.markdown("**Mosca's inequality:** at risk if *years secret* + *years to migrate* > *years until the threat*")
        c1, c2, c3, c4 = st.columns(4)
        m_sens = c1.select_slider("Sensitivity", options=list(SENSITIVITIES), value="High", key="m_sens")
        m_x = c2.number_input("Years secret (x)", 1, 50, 5)
        m_y = c3.number_input("Years to migrate (y)", 0, 20, int(DEFAULT_MIGRATION_YEARS))
        m_z = c4.number_input("Years until threat (z)", 1, 50, int(DEFAULT_THREAT_YEARS))
        m = advise(m_sens, m_x, m_y, m_z)
        st.metric(
            "x + y vs z",
            f"{m.exposure_years:g} vs {m.threat_years:g} years",
            "at risk" if m.at_risk else "safe",
            delta_color="inverse" if m.at_risk else "normal",
        )
        st.markdown(f"**{m.profile}.** {m.reason}")
        st.caption("y and z are assumptions you can change, not facts. Source: Mosca's inequality (arXiv 2603.06969).")

    st.subheader("Classical vs Hybrid: measured cost")
    st.caption(
        "Classical = X25519 + Ed25519. Hybrid = X25519 + ML-KEM-768 + ML-DSA-65. "
        "Real primitives from the `cryptography` library, timed on this machine (median)."
    )
    bench = cached_benchmark()
    times = pd.DataFrame(bench["timings"]).set_index("operation")
    times.columns = ["Classical (ms)", "Hybrid (ms)"]
    st.bar_chart(times, horizontal=True, stack=False)
    sizes = pd.DataFrame(bench["sizes"]).set_index("artifact")
    sizes.columns = ["Classical (bytes)", "Hybrid (bytes)"]
    st.dataframe(sizes, width="stretch")
    st.caption("Hybrid costs more bytes and a little more time, but a quantum attacker must break both halves.")

# ==================================================================
# QISKIT LAB — the quantum step that breaks RSA and ECC
# ==================================================================
with tab_lab:
    st.subheader("Order-finding: the quantum heart of Shor's algorithm")
    st.markdown(
        "RSA and elliptic-curve keys are safe only because factoring is slow. Factoring reduces to "
        "**order-finding**: the smallest *r* with *a^r mod N = 1*. A quantum computer finds *r* quickly; "
        "the factors then follow from ordinary arithmetic. Lattice problems (ML-KEM, ML-DSA) have no such "
        "repeating pattern, which is why they are the post-quantum answer."
    )
    a = st.select_slider("Base a (N = 15)", options=[2, 4, 7, 8, 11, 13, 14], value=7)
    counts, order, factors, drawing = cached_order(a)

    left, right = st.columns([3, 2])
    with left:
        st.markdown("**1. Measure the counting register** (1024 shots spread over the peaks)")
        st.bar_chart(pd.DataFrame({"Count": counts}).sort_index())
    with right:
        st.markdown("**2. Read the period from the peaks**")
        st.markdown(
            f"Peaks at multiples of 8 / r, so **r = {order}** (check: {a}^{order} mod 15 = {pow(a, order, 15)})."
        )
        st.markdown("**3. Factor N with gcd**")
        if factors:
            h = pow(a, order // 2)
            st.markdown(
                f"gcd({h} − 1, 15) = **{gcd(h - 1, 15)}**, gcd({h} + 1, 15) = **{gcd(h + 1, 15)}** → 15 = {factors[0]} × {factors[1]}"
            )
        else:
            st.markdown("This base gives no factors (odd order or trivial gcd); Shor would retry with another base.")

    with st.expander("The circuit (3 counting qubits + 4 work qubits)"):
        st.code(drawing, language="text")
    st.info(
        "Educational scale: a simulator handles N = 15, while real RSA keys need thousands of error-corrected "
        "qubits. The point is the method: once such machines exist, today's recorded traffic can be decrypted."
    )
