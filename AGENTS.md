# AGENTS.md — Master Agentic & Human Operating System
# Qiskit Fall Fest 2026 | Quantum Hack Day
# TinkerSpace, Kochi | 1 Nov 2026 | 10:00 AM – 5:00 PM

> **Audience**: Dual-purpose operational manual for **AI Coding Agents** and the **3 human teammates**.  
> **Project**: CipherCanvas — Intelligent Post-Quantum Data Protection and Secure Media Vault  
> **Core Objective**: Deliver a working end-to-end hybrid PQC media vault with HNDL risk advice, tamper detection, CBOM, and an explainable Qiskit threat lab — all demonstrable live by 5 PM.

---

## 0. Team & Roles (Locked)

| Member     | Role                          | Main Deliverable                                              |
|------------|-------------------------------|---------------------------------------------------------------|
| **Melvin** | Cryptography Engineer         | Hybrid PQC encryption, AES-GCM, ML-DSA, key management, shared envelope format |
| **Arunima**| Full-stack / Media Engineer   | Streamlit UI, PNG LSB embed/extract, tamper-detection lab     |
| **Maheshwar** | Quantum / Security Engineer | HNDL risk advisor, Qiskit Aer lab, CBOM generator, Classical vs Hybrid benchmarks |

**First action (before any feature work)**: Melvin publishes the shared encryption envelope schema. Arunima and Maheshwar must not invent their own payload formats.

---

## 1. Golden Rules of Engagement

1. **Explainability Over Magic**  
   Every cryptographic choice and every quantum circuit must be explainable in 30–60 seconds. Agents and humans reject opaque implementations.

2. **Setup First, Then Experiment**  
   Python 3.12 via `uv`, project venv, Qiskit + Aer, and (if possible) liboqs must work before feature code. Classical-only fallback is mandatory.

3. **Simulator First, Real Hardware Second**  
   All Qiskit work runs on `AerSimulator`. IBM Quantum is optional and secondary.

4. **Anti-Overengineering (YAGNI & KISS)**  
   Freeze scope early. No multi-file vault, time-capsule, chat archive, or complex agility engine until the core Alice→Bob flow works.

5. **Interactive Token Efficiency Guard**  
   Never generate more than ~60–80 lines of new code without human confirmation. Ask 1–2 crisp questions before non-trivial design choices.

6. **Keep Secrets Private**  
   No private keys, API tokens, or raw secrets in notebooks, Git, or screenshots.

7. **Integration Over Parallel Perfection**  
   Modules that cannot exchange data are failures, even if each works in isolation.

---

## 2. Project Positioning & Problem Statement

**Name**: CipherCanvas – Intelligent Post-Quantum Data Protection and Secure Media Vault

**Problem**: Sensitive information encrypted today can be harvested and stored for later decryption once large-scale quantum computers arrive (Harvest Now, Decrypt Later). Most people lack simple tools to protect messages with hybrid post-quantum cryptography, assess long-term confidentiality needs, verify authenticity, detect tampering, and understand the migration path to quantum-resistant algorithms.

**Solution**: CipherCanvas turns ordinary PNG images into encrypted vaults using hybrid classical + post-quantum cryptography (X25519 + ML-KEM, AES-256-GCM, ML-DSA). It provides an explainable HNDL risk advisor, a cryptographic bill-of-materials (CBOM) for each protected message, interactive tamper detection, and a Qiskit-based quantum threat explanation lab.

**One-line pitch**: CipherCanvas turns ordinary images into quantum-ready encrypted vaults while helping users understand HNDL risk, verify authenticity, and prepare for post-quantum cryptography.

**Competitive advantage** (three pillars):
- **Protect** — Hybrid post-quantum encryption + signatures
- **Assess** — Intelligent HNDL risk analysis
- **Demonstrate** — Quantum threat visualization + measurable cryptographic comparisons

---

## 3. Must-Ship MVP (Frozen Scope)

Do these first. Everything else is stretch only after the full flow works.

1. End-to-end vault flow  
   Image + message + recipient → Hybrid encrypt + sign → LSB embed in PNG → extract + verify + decrypt.

2. Simple HNDL / confidentiality-lifetime risk advisor  
   Inputs: sensitivity + retention years.  
   Output: recommended profile (Classical / Hybrid / PQC-only) + short explanation.

3. Tamper-detection interactive demo  
   Original verifies; modified payload or metadata fails clearly.

4. One meaningful Qiskit Aer lab  
   Educational circuit showing why order-finding/factoring threatens RSA/ECC and why lattice-based PQC responds. Heavily commented.

5. Minimal CBOM  
   JSON (or pretty print) per protected message: algorithms, profile, timestamp, `pqc_ready`.

6. Basic Classical vs Hybrid size/time comparison.

**Explicitly deferred**: full cryptographic agility runtime engine, multi-file vault, time-capsule, chat archive, fancy multi-chart dashboards.

---

## 4. Shared Encryption Envelope (Define First)

Melvin owns this schema and publishes it immediately. All modules consume the same format.

Required fields (minimum):
- `version`
- `sender_id`
- `recipient_id`
- `algorithms` (key establishment, encryption, signature)
- `kem_ciphertext`
- `ephemeral_public_key`
- `aes_gcm_nonce`
- `encrypted_payload`
- `signature`

Signature must cover the relevant envelope fields (not just the raw ciphertext).  
AES-GCM already authenticates the payload; ML-DSA authenticates the sender when the verification key is trusted.

---

## 5. Real-Time Timeline & Integration Checkpoints (Team of 3)

```
10:00      11:00      12:00      13:00      14:00      15:00      16:00      17:00
  │          │          │          │          │          │          │          │
  ├─ SETUP ──┼─ CORE ───┼─ WIRE ───┼─ LUNCH ──┼─ INTEGRATE ┼─ POLISH ─┼─ DEMO ──┤
```

| Time | Focus | Melvin | Arunima | Maheshwar | Checkpoint |
|------|-------|--------|---------|-----------|------------|
| 10:00–10:40 | Setup + schema | `uv` env, envelope schema, key stubs | Streamlit shell, PNG load/save | Qiskit verify, CBOM schema draft | All three environments work; envelope schema published |
| 10:40–12:00 | Core modules | Hybrid encrypt/sign/decrypt path | LSB embed + extract | HNDL advisor logic + Qiskit circuit | Modules have basic working interfaces |
| 12:00–13:00 | First integration | Crypto ↔ media test vectors | Accept envelope, embed/extract | Consume envelope for CBOM | Crypto and media exchange test data |
| 13:00–13:30 | Lunch + sync | — | — | — | Blockers listed |
| 13:30–15:00 | Full pipeline | Receiver path solid | Tamper lab in UI | Risk advisor + CBOM in UI | Complete encrypt → embed → extract → verify → decrypt |
| 15:00–16:00 | Integration + polish | Classical fallback path | Demo polish, error messages | Benchmarks + Qiskit lab text | All three modules integrated |
| 16:00–17:00 | Demo readiness | — | — | — | Full dry-run + backup classical demo + presentation script |

**Backup rule**: If liboqs / PQC installation fails, demonstrate the full workflow with a clearly labelled Classical path and a separate, honest PQC explanation. Never fake live PQC operations.

---

## 6. Final MVP Architecture

```
Streamlit Application
        │
        ▼
User uploads image + enters confidential message + recipient
        │
        ▼
HNDL Risk Advisor  ←── Maheshwar
(sensitivity + lifetime → Classical / Hybrid / PQC-only)
        │
        ▼
Hybrid Cryptography Engine  ←── Melvin
(X25519 + ML-KEM → HKDF → AES-256-GCM → ML-DSA)
        │
        ▼
PNG Media Vault  ←── Arunima
(embed encrypted envelope / extract at receiver)
        │
        ▼
Verification (signature + tamper detection)
        │
        ├──► CBOM (cryptographic inventory)  ←── Maheshwar
        └──► Qiskit Lab (quantum threat education)  ←── Maheshwar
```

---

## 7. Demo Story for Judges (One Continuous Narrative)

1. Alice has confidential information that must remain private for five years.  
2. CipherCanvas identifies the potential HNDL risk.  
3. The system recommends hybrid post-quantum protection.  
4. Alice embeds the encrypted message inside an ordinary PNG.  
5. Bob extracts and verifies the message.  
6. You demonstrate tamper detection (modified payload fails).  
7. Dashboard / printout shows CBOM + Classical vs Hybrid numbers.  
8. Qiskit lab explains the quantum threat and why the chosen algorithms resist it.

This story links problem → assessment → protection → verification → quantum understanding.

---

## 8. Official Setup Reference (`uv` + Python 3.12)

```bash
# Install uv (one-time)
curl -LsSf https://astral.sh/uv/install.sh | sh          # macOS/Linux
# Windows PowerShell: irm https://astral.sh/uv/install.ps1 | iex

mkdir ciphercanvas && cd ciphercanvas
uv python install 3.12
uv venv --python 3.12 .venv
source .venv/bin/activate          # or Windows equivalent

uv pip install qiskit qiskit-aer qiskit-ibm-runtime matplotlib pylatexenc jupyter
# + streamlit pillow numpy cryptography
# + liboqs-python / oqs if available (test early!)

python -c "import qiskit; print(qiskit.__version__)"
```

Classical fallback libraries must be installed even if PQC fails.

---

## 9. Agent Skills & Free Tooling (Still Apply)

- Progressive disclosure + keyword discovery + Superpowers remain the skill loading model.
- Free MCP servers (Context7, filesystem, git, github) preferred.
- Free agents (Aider, OpenCode, Cline, Continue, etc.) as previously listed.
- Always prefer Context7 for current library docs over hallucinated APIs.

---

## 10. Troubleshooting Quick Hits

| Symptom | Fix |
|---------|-----|
| `uv` not found | Re-install + restart shell |
| `No module named qiskit` | Activate `.venv`, then `uv pip install ...` |
| liboqs / PQC fails | Switch to labelled Classical path; keep Qiskit lab |
| Modules disagree on payload | Re-check Melvin’s shared envelope schema |
| Integration late | Use the hourly checkpoints; do not wait until hour 6 |

---

## 11. Quick Command Reference

```bash
uv python install 3.12
uv venv --python 3.12 .venv
source .venv/bin/activate
uv pip install qiskit qiskit-aer streamlit pillow numpy cryptography ...
python -c "import qiskit; print(qiskit.__version__)"
streamlit run app.py
```

---

**End of AGENTS.md**  
Scope is frozen to the Must-Ship MVP. Melvin owns the envelope. Integration checkpoints are mandatory. Classical fallback is required. The first milestone is a working Alice → encrypt → embed → Bob extract → verify → decrypt path. Everything else builds on that success.
