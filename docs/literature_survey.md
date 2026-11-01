"""
Literature survey for CipherCanvas: what recent arXiv work covers, and where our MVP differs.
Required by AGENTS.md Section 14. Cite entries here in module docstrings.
"""

# Literature Survey (1 Nov 2026)

> Method: arXiv searches using the dorks in AGENTS.md Section 14. Findings come from search summaries and abstracts, **not full-paper reads**. Verify each claim in the paper before quoting it on stage.

## 1. HNDL risk assessment (supports the advisor)

| Paper | What it does | Gap we fill |
|---|---|---|
| [2603.06969](https://arxiv.org/abs/2603.06969) Securing Cryptography in the Age of Quantum Computing and AI | Uses Mosca's inequality: data shelf life + migration time vs. time to a quantum threat | Framework only; no end-user tool |
| [2609.26225](https://arxiv.org/abs/2609.26225) Quantum-Ready Secure WAN | Risk assessment and staged migration for enterprise WANs | Enterprise network scope, not per-message |
| [2605.02276](https://arxiv.org/abs/2605.02276) Australian real-time payments (Monte Carlo) | Estimates retroactive exposure of recorded transactions | Single sector, simulation study |

**Use in our advisor:** frame the rule as Mosca's inequality. Retention years = shelf life. Output Hybrid or PQC-only when shelf life + assumed migration time exceeds an assumed time-to-threat. State the assumed timeline openly; it is a policy input, not a fact.

## 2. Hybrid ML-KEM + X25519 (supports the crypto engine)

| Paper | What it does | Implication for us |
|---|---|---|
| [2609.21273](https://arxiv.org/abs/2609.21273) Transcript-bound combiners | Shows a plain `KDF(K_pq ‖ K_ec)` combiner can be silently downgraded to classical by an active attacker; a transcript-bound one aborts | Our signature covers the `algorithms` field of the envelope, which blocks a silent downgrade. Also feed the algorithm list and KEM ciphertexts into HKDF `info`. |
| X-Wing (cited in 2609.21273) | Fixed ML-KEM-768 + X25519 combiner with IND-CCA proof | Reference design to cite for "why hybrid" |
| [2610.16100](https://arxiv.org/abs/2610.16100) HDKEM, [2509.01701](https://arxiv.org/abs/2509.01701) AmphiKey | Authenticated / deniable hybrid key exchange | Out of scope; we sign with ML-DSA instead |

## 3. Closest existing tool

[2605.17061](https://arxiv.org/abs/2605.17061) **quantum-safe** (Python, hybrid-by-default). X25519 + ML-KEM-768, ML-DSA-65, CycloneDX CBOM, ACVP known-answer tests. It is a **library**: no end-user flow, no risk advice, no steganography, no teaching lab. This is the competitor to acknowledge, and a possible dependency to compare against.

## 4. CBOM

| Paper | Finding | Implication |
|---|---|---|
| [2603.22442](https://arxiv.org/abs/2603.22442) Architecture-derived CBOMs | Most CBOMs are inventory-derived, lacking context and rationale | Ours is per message and records the profile chosen and why |
| [2608.04857](https://arxiv.org/abs/2608.04857) Static discovery of crypto assets | Scanner emits CycloneDX CBOM for whole codebases | Different problem: we describe one protected message |
| [2609.07849](https://arxiv.org/abs/2609.07849) Nothing Breaks | A CBOM tool gave the same readiness score (49.4) for 12 different configurations | Compute `pqc_ready` from the algorithms actually used; never a constant |

Format reference: OWASP CycloneDX. Consider matching its field names.

## 5. Steganography

No arXiv paper found combining PNG LSB with a post-quantum cipher. Nearest: [2604.26413](https://arxiv.org/abs/2604.26413) Quantum Gatekeeper (PNG LSB + AES-GCM, quantum-derived key; payload cipher is not post-quantum) and [2506.13895](https://arxiv.org/abs/2506.13895) (ElGamal + LSB in QR codes; not post-quantum). Absence from a few searches is **not proof** nobody has done it; phrase as "we did not find".

## 6. Quantum lab

Small-scale Shor demos exist ([2304.04411](https://arxiv.org/abs/2304.04411) Qiskit small-key RSA attack; [2403.17485](https://arxiv.org/abs/2403.17485) hands-on education; Qiskit textbook Shor notebook cited in [2505.03743](https://arxiv.org/abs/2505.03743)). A simulator cannot factor real keys ([2605.03951](https://arxiv.org/abs/2605.03951) notes 2048-bit RSA needs well beyond simulable qubit counts). Our lab is **educational, not novel**; its value is linking the circuit to the algorithm choices in the app.

## Innovation wedge (honest version)

Existing work is strong on pieces: risk frameworks, hybrid combiners, CBOM inventories, PQC libraries. We did not find one **end-user flow** that joins: HNDL advice → hybrid PQC protection with a signed envelope → image carrier → tamper demo → per-message CBOM → quantum explanation.
We do **not** claim: new cryptography, a new combiner, undetectable steganography, or a novel Shor implementation. LSB hiding gives obscurity, not security; the security comes from the encryption.

## Action items from the survey

- [ ] Bind `algorithms` and KEM ciphertexts into the HKDF `info` field (Melvin).
- [ ] Derive `pqc_ready` from actual algorithms used, with a test that two profiles give different values (Maheshwar).
- [ ] Phrase the advisor rule as Mosca's inequality and expose the assumed timeline (Maheshwar).
- [ ] Add a "related work" slide: quantum-safe (library), transcript-bound combiners, CBOM critique.
