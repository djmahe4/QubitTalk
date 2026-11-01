# AGENTS.md — Master Agentic & Human Operating System
# Qiskit Fall Fest 2026 | Quantum Hack Day
# TinkerSpace, Kochi | 1 Nov 2026 | 10:00 AM – 5:00 PM

> **Audience**: Dual-purpose operational manual for **AI Coding Agents** and **any human team (1–N people) who fork this repo**. See [Section 12](#12-fork--use-this-template) to adapt it.  
> **Project**: CipherCanvas — Intelligent Post-Quantum Data Protection and Secure Media Vault  
> **Core Objective**: Deliver a working end-to-end hybrid PQC media vault with HNDL risk advice, tamper detection, CBOM, and an explainable Qiskit threat lab — all demonstrable live by 5 PM.

---

## 0. Team & Roles (Reference Team — Replace When Forking)

The original Qiskit Fall Fest team is shown below as an example. Forkers: keep the three roles (Crypto, Media/UI, Quantum/Security) but assign your own names, or merge roles if you are fewer than three.

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

8. **Defensible Ownership**  
   Each human must be able to explain, in 30 seconds, any algorithm, data shape, or error boundary they committed. If they cannot, the agent simplifies or rejects the code. Commit under your own Git identity so judges can attribute work.

9. **Academic & Standards Grounding**  
   Before non-trivial crypto, risk-scoring, or quantum-circuit logic, consult `docs/literature_survey.md`. Core modules cite their source (NIST FIPS, RFC, or arXiv paper) in the module docstring. See [Section 14](#14-grounding--literature-survey).

10. **Test-Driven Development**  
    Write tests before or in lockstep with code. Every module needs a happy-path test, a boundary/validation test, and a failure-mode test. See [Section 15](#15-tdd--quality-gates).

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

- Skills are folders with a `SKILL.md`. **Progressive disclosure**: only `name` + `description` are always in context; the body loads on a match; `references/` and `scripts/` load only when the body points to them. Never dump full skill bodies into the system prompt.
- If no local skill matches, do a **keyword search** of the skill index, load only the one matching `SKILL.md`, and never invent a procedure.
  - **Index**: `https://aaskills.tech/skills.json` (Agentic Awesome Skills). It is one large JSON array (over 2 MB), so never load it into context whole; filter it with a script or `jq` and keep only the top few matches.
  - **Entry fields**: `id`, `name`, `path` (e.g. `skills/security/<id>`), `category`, `description`, `risk` (`none` / `safe` / `critical` / `offensive`), `source`, and `plugin.targets` (Claude/Codex support).
  - **Search**: score entries by how many task keywords appear in `id` + `name` + `description`; show the human only `name` + `description` + `risk` for the top 3–5.
  - **Load**: fetch `<path>/SKILL.md` from the index's source repo (believed to be `sickn33/agentic-awesome-skills` on GitHub; verify before relying on it) into the local skills folder. Load only the chosen skill.
  - **Subfiles (dynamic loading)**: after fetching `SKILL.md`, scan its body for relative links or paths (`references/*.md`, `scripts/*`, `assets/*`, sibling `*.md`). Do not bulk-download the folder. Fetch each subfile from `<path>/<subfile>` only at the step that needs it, and keep it in context only while that step runs. List the folder via the GitHub contents API (`https://api.github.com/repos/<owner>/<repo>/contents/<path>`) only if `SKILL.md` references a file you cannot resolve, or the human asks for the full skill.
  - **Nested references**: if a subfile points to further files, apply the same rule. Stop at two levels deep and ask the human before going further.
  - **Cache locally**: save fetched subfiles beside `SKILL.md` in the local skills folder (same relative layout) so later steps and other agents reuse them instead of re-fetching.
  - **Scripts**: never execute a fetched script. Read it, tell the human what it does, and run it only after approval.
  - **Safety**: skills are third-party instructions. Skip `critical` and `offensive` risk entries, read the `SKILL.md` before first use, and get human approval before loading. Never run scripts a skill ships without reading them.
  - Example filter: `curl -s https://aaskills.tech/skills.json | jq '[.[] | select((.description + .name) | test("tdd|test-driven"; "i")) | {name, path, risk}] | .[:5]'`
- **Superpowers** ([obra/superpowers](https://github.com/obra/superpowers)) is the recommended ready-made pack. Core skills to have locally: `test-driven-development`, `systematic-debugging`, `verification-before-completion`, `brainstorming`.
- Free MCP servers (Context7, filesystem, git, github) preferred.
- Free agents (Aider, OpenCode, Cline, Continue, etc.) as previously listed.
- Always prefer Context7 for current library docs over hallucinated APIs.
- Use **Kilo Code** for independent code review (see [Section 13](#13-code-review-with-kilo-code-recommended)).

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

## 12. Fork & Use This Template

Anyone can fork this repo and run their own CipherCanvas build, hackathon, or workshop.

1. **Fork** the repo on GitHub, then clone your fork.
2. **Edit Section 0**: replace names with your team. Solo? One person owns all three roles; do them in the order Crypto → Media → Quantum.
3. **Edit the header and Section 5**: change event name, date, venue, and rescale the timeline to your available hours. Keep the checkpoints (schema first, integration mid-way, dry-run last).
4. **Run Section 8 setup** and confirm `import qiskit` works before feature code.
5. **Publish the envelope schema first** (Section 4). The Crypto owner commits it before anyone else writes code.
6. **Keep scope frozen** to Section 3 until the Alice → Bob flow works end to end.
7. **Never commit secrets** (Golden Rule 6). Add key files and `.env` to `.gitignore`.
8. **Contribute back**: improvements to this file are welcome via pull request.

AI agents: when working in a fork, read Section 0 for the current team's roles rather than assuming the original names.

---

## 13. Code Review with Kilo Code (Recommended)

We suggest [Kilo Code](https://kilocode.ai) (VS Code extension / CLI) as an independent reviewer, so the model that wrote the code is not the only one checking it.

- **When**: before each integration checkpoint in Section 5 and before the final dry-run.
- **Scope the review**: ask it to check one module or one diff at a time.
- **Review checklist** (paste into Kilo Code):
  - Does the code match the shared envelope schema exactly?
  - Does the signature cover the envelope fields, not just the ciphertext?
  - Are nonces unique per encryption and never reused with the same key?
  - Are secrets, private keys, or tokens absent from code, logs, and notebooks?
  - Is the PQC path real, or clearly labelled Classical when liboqs is unavailable?
  - Is the code explainable in 30–60 seconds, and within the frozen MVP scope?
- **Humans decide**: treat Kilo Code findings as suggestions. A teammate confirms every crypto-related change before merge.
- Any other reviewer (Claude Code `/code-review`, a teammate, a PR review) is a fine substitute; the point is a second pair of eyes.

---

## 14. Grounding & Literature Survey

Ground the team in standards and research before writing core logic. Output goes in `docs/literature_survey.md` (create it in the first 40 minutes; keep it to one page per topic).

### Primary sources (prefer these over blog posts)
- ML-KEM: NIST FIPS 203. ML-DSA: NIST FIPS 204.
- X25519: RFC 7748. HKDF: RFC 5869. AES-GCM: NIST SP 800-38D.
- Shor's algorithm: Shor 1994, arXiv:quant-ph/9508027 (basis for the Qiskit lab).
- Hybrid key-establishment combiners: IETF hybrid key exchange drafts (verify current draft names before citing).

### arXiv search dorks
```text
site:arxiv.org/abs ("harvest now decrypt later") ("risk" OR "migration" OR "timeline")
site:arxiv.org/abs ("hybrid" "ML-KEM" OR "Kyber") ("X25519") ("key exchange" OR "combiner")
site:arxiv.org/abs ("cryptographic bill of materials" OR "CBOM" OR "crypto agility")
site:arxiv.org/abs ("Shor" OR "order finding") ("Qiskit" OR "circuit") ("RSA" OR "elliptic curve")
site:arxiv.org/abs ("LSB steganography" OR "PNG steganography") ("encrypted payload")
```

### Fast HTML reading (skip token-heavy PDFs)
- `https://arxiv.org/html/<arxiv_id>` or `https://ar5iv.labs.arxiv.org/html/<arxiv_id>`
- Extract exactly three things: (1) the problem formulation, (2) the baseline / standard approach, (3) its limitations for a small hackathon demo.

### The innovation wedge
Write one paragraph: what CipherCanvas simplifies or combines that the sources treat separately (e.g. HNDL advice + hybrid encryption + CBOM in one explainable flow). Reference it in module docstrings. Never claim a security property the sources do not support.

---

## 15. TDD & Quality Gates

1. **Red → Green → Refactor.** Write one failing test, ask the human 1–2 calibration questions if the interface is unclear, write the smallest passing code, then add boundary and failure tests.
2. **Required tests per module** (crypto, media, advisor, CBOM):
   - Happy path (e.g. encrypt → embed → extract → verify → decrypt round-trips).
   - Boundary/validation (empty message, oversized payload for the image, bad retention years).
   - Failure mode (flipped ciphertext bit, altered metadata, wrong recipient key → must fail clearly, never silently).
3. **Known-answer tests**: use official test vectors where a library provides them. Never write a test that only passes because the code under test mocks the crypto.
4. **Tooling**: `ruff check .`, `ruff format .`, `pytest`. Run all three before opening a PR. Use type hints and explicit schemas (e.g. Pydantic or dataclasses) for the envelope.
5. **Safe error boundaries**: catch specific exceptions only, never bare `except Exception`; verification failures return a clear reason, not a stack trace; no secrets in logs.
6. **Docs via Context7** for library calls (`cryptography`, `oqs`, `qiskit`, `streamlit`, `pillow`); do not guess signatures.

---

## 16. Git, PR & Defense Protocol

### Git identity (before the first commit)
```bash
git config user.name "<your GitHub username>"
git config user.email "<your email>"
```

### Micro-issues and PRs
- One issue = one focused unit, under ~150 lines of diff, with acceptance criteria: 1 happy-path test, 1 validation test, 1 failure test.
- Branch: `feature/<issue>-<slug>`. Commits: Conventional Commits (`feat(crypto): ...`, `test(media): ...`, `fix(ui): ...`).
- Squash and merge after one teammate approves and `pytest` is green (preserves author attribution). Solo forkers self-review with Kilo Code ([Section 13](#13-code-review-with-kilo-code-recommended)).

### PR template
```markdown
## Summary
Closes #<n>. <what changed, under 150 lines>

## Verification
- [ ] ruff clean  - [ ] pytest passes  - [ ] reviewed

## Defense brief (3 bullets)
1. Decision rationale: why this algorithm / data shape
2. Error handling: how failures and tampering are handled
3. Source: which standard or paper this follows
```

### Judge Q&A formulas (30–60 seconds each)
- **"Why this algorithm?"** Cite the standard or paper from `docs/literature_survey.md`, state what we simplified, point to the test that shows it works.
- **"Why hybrid?"** X25519 protects against classical attackers today, ML-KEM against future quantum ones; an attacker must break both. Signature covers the envelope fields so tampering fails verification.
- **"What if PQC fails to install?"** We run the labelled Classical path and say so honestly; no PQC operation is ever faked.
- **"How do you detect tampering?"** AES-GCM tag fails on payload changes, ML-DSA signature fails on metadata changes; the tamper lab demonstrates both.

---

**End of AGENTS.md**  
Scope is frozen to the Must-Ship MVP. Melvin owns the envelope. Integration checkpoints are mandatory. Classical fallback is required. The first milestone is a working Alice → encrypt → embed → Bob extract → verify → decrypt path. Everything else builds on that success.
