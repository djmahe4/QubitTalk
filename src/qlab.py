"""Qiskit lab: the quantum step of Shor's algorithm, run on a simulator.

Why this matters for CipherCanvas: RSA and elliptic-curve keys are safe only because
factoring (or a discrete log) is slow on a normal computer. Both reduce to ORDER-FINDING:
given a and N, find the smallest r > 0 with a^r = 1 (mod N). A quantum computer can find r
fast. Knowing r, the factors of N fall out of simple classical arithmetic.

Lattice problems (ML-KEM, ML-DSA) have no known period structure like this, which is why
they are the post-quantum answer. This lab is educational: a simulator can only do tiny N.

Source: Shor 1994, arXiv:quant-ph/9508027 (see docs/literature_survey.md section 6).
"""

from dataclasses import dataclass
from fractions import Fraction
from math import gcd

import numpy as np
from qiskit import QuantumCircuit, transpile
from qiskit.circuit.library import QFTGate, UnitaryGate
from qiskit_aer import AerSimulator

WORK_QUBITS = 4  # enough to hold any number below N = 15


@dataclass(frozen=True)
class OrderResult:
    a: int
    n: int
    counts: dict  # measured counting-register value -> times seen
    order: int | None  # r, or None if this run was unlucky
    factors: tuple | None  # (p, q) with p * q == N
    circuit: QuantumCircuit


def _multiply_gate(factor: int, n: int) -> UnitaryGate:
    """Unitary that maps |y> to |factor * y mod N>. A permutation, so it is a valid quantum gate."""
    size = 2**WORK_QUBITS
    matrix = np.zeros((size, size))
    for y in range(size):
        matrix[(factor * y) % n if y < n else y, y] = 1  # states >= N are left alone
    return UnitaryGate(matrix, label=f"x{factor} mod {n}")


def build_circuit(a: int, n: int, counting: int) -> QuantumCircuit:
    """Quantum phase estimation of 'multiply by a mod N'. Its phase is s/r, which reveals r."""
    qc = QuantumCircuit(counting + WORK_QUBITS, counting)
    qc.x(counting)  # work register starts as |1>
    qc.h(range(counting))  # counting register in superposition: try every power at once
    for k in range(counting):
        # Controlled "multiply by a^(2^k) mod N": the bit k of the counting register decides.
        qc.append(_multiply_gate(pow(a, 2**k, n), n).control(1), [k, *range(counting, counting + WORK_QUBITS)])
    qc.append(QFTGate(counting).inverse(), range(counting))  # turn the phase into a readable number
    qc.measure(range(counting), range(counting))
    return qc


def find_order(a: int = 7, n: int = 15, counting: int = 3, shots: int = 1024, seed: int = 7) -> OrderResult:
    """Run the circuit, then do the classical post-processing that turns counts into r and factors."""
    if n != 15 or gcd(a, n) != 1 or not 1 < a < n:
        raise ValueError("This lab only supports N = 15 and a coprime to 15 (2, 4, 7, 8, 11, 13, 14).")
    qc = build_circuit(a, n, counting)
    backend = AerSimulator(seed_simulator=seed)
    counts = backend.run(transpile(qc, backend), shots=shots).result().get_counts()
    counts = {int(bits, 2): c for bits, c in counts.items()}

    order = None
    for measured in sorted(counts, key=counts.get, reverse=True):
        # measured / 2^counting ~ s/r; the denominator of that fraction is a candidate r.
        r = Fraction(measured, 2**counting).limit_denominator(n).denominator
        if pow(a, r, n) == 1:  # keep only a real order
            order = r
            break

    factors = None
    if order and order % 2 == 0:
        p, q = gcd(pow(a, order // 2) - 1, n), gcd(pow(a, order // 2) + 1, n)
        if p * q == n and 1 < p < n:
            factors = tuple(sorted((p, q)))
    return OrderResult(a, n, counts, order, factors, qc)
