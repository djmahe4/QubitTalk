"""Password and passphrase strength analyzer for Qubit Talks.

Evaluates length, character diversity, entropy, and classical vs quantum (Grover)
crack resistance. Standards: NIST SP 800-63B (Digital Identity Guidelines).
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

COMMON_PATTERNS = [
    "password",
    "123456",
    "12345678",
    "qwerty",
    "admin",
    "welcome",
    "qubit",
    "quantum",
]


@dataclass(frozen=True)
class PasswordAnalysis:
    score: int  # 0 to 100
    level: str  # "Weak", "Medium", "Hard"
    color: str  # CSS color
    entropy_bits: float
    passed_min_length: bool
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    feedback: list[str]
    classical_crack_time: str
    quantum_crack_time: str


def _format_time(seconds: float) -> str:
    if seconds < 0.001:
        return "< 1 millisecond"
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365:
        return f"{days:.1f} days"
    years = days / 365.25
    if years < 1_000:
        return f"{years:.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    return f"{years / 1_000_000_000:.1f} billion years"


def analyze_password_strength(password: str) -> PasswordAnalysis:
    """Analyze a password/passphrase and return detailed security metrics."""
    if not password:
        return PasswordAnalysis(
            score=0,
            level="Weak",
            color="#EF4444",
            entropy_bits=0.0,
            passed_min_length=False,
            has_lower=False,
            has_upper=False,
            has_digit=False,
            has_symbol=False,
            feedback=["Password is empty. Enter at least 8 characters."],
            classical_crack_time="Instant",
            quantum_crack_time="Instant",
        )

    length = len(password)
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))

    # Calculate charset pool size
    pool = 0
    if has_lower:
        pool += 26
    if has_upper:
        pool += 26
    if has_digit:
        pool += 10
    if has_symbol:
        pool += 33

    entropy = length * math.log2(pool) if pool > 0 else 0.0

    # Base score calculated from length and diversity
    score = 0
    feedback: list[str] = []

    # Length evaluation
    if length >= 14:
        score += 40
    elif length >= 12:
        score += 35
    elif length >= 8:
        score += 20
    else:
        score += max(0, length * 2)
        feedback.append("Use at least 8 characters (12+ recommended).")

    # Variety evaluation
    diversity_count = sum([has_lower, has_upper, has_digit, has_symbol])
    score += diversity_count * 12

    if not has_lower or not has_upper:
        feedback.append("Mix lowercase and uppercase letters.")
    if not has_digit:
        feedback.append("Add at least one number.")
    if not has_symbol:
        feedback.append("Add special symbols (e.g. !, @, #, $, %).")

    # Pattern and repetition penalties
    lower_pw = password.lower()
    for pattern in COMMON_PATTERNS:
        if pattern in lower_pw:
            ratio = len(pattern) / length
            penalty = int(25 * ratio)
            score -= max(5, penalty)
            feedback.append(f"Contains common word or pattern '{pattern}'.")
            break

    if re.search(r"(.)\1{2,}", password):
        score -= 10
        feedback.append("Avoid repeating the same character 3+ times.")

    # Clamp score
    score = max(0, min(100, score))

    # Classification
    if length < 8 or score < 45 or entropy < 35:
        level = "Weak"
        color = "#EF4444"
        score = min(score, 40)
    elif score < 75 or entropy < 60:
        level = "Medium"
        color = "#F59E0B"
    else:
        level = "Hard"
        color = "#10B981"

    if not feedback:
        feedback.append("Excellent passphrase with high entropy!")

    # Classical brute-force crack time @ 10^9 guesses/sec
    guesses = 2**entropy
    classical_sec = guesses / 1e9
    classical_time = _format_time(classical_sec)

    # Quantum Grover search speedup: O(sqrt(N)) queries @ 10^7 quantum checks/sec
    grover_queries = 2 ** (entropy / 2)
    quantum_sec = grover_queries / 1e7
    quantum_time = _format_time(quantum_sec)

    return PasswordAnalysis(
        score=score,
        level=level,
        color=color,
        entropy_bits=round(entropy, 1),
        passed_min_length=(length >= 8),
        has_lower=has_lower,
        has_upper=has_upper,
        has_digit=has_digit,
        has_symbol=has_symbol,
        feedback=feedback,
        classical_crack_time=classical_time,
        quantum_crack_time=quantum_time,
    )
