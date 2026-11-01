"""HNDL risk advisor: how long must this stay secret, and what protection does that need?

Grounding: Mosca's inequality. If data shelf life (x) plus the time to migrate
(y) exceeds the time until a quantum computer can break today's public-key
crypto (z), then data protected only classically is already at risk, because
an attacker can record it now and decrypt it later (Harvest Now, Decrypt Later).
See docs/literature_survey.md section 1 (arXiv 2603.06969).

y and z are ASSUMPTIONS, not facts. They are inputs, shown to the user, never hidden.
"""

from dataclasses import dataclass

SENSITIVITIES = ("Low", "Medium", "High", "Critical")
DEFAULT_MIGRATION_YEARS = 2.0  # assumed time to move systems to PQC
DEFAULT_THREAT_YEARS = 10.0  # assumed years until a quantum computer breaks RSA/ECC


@dataclass(frozen=True)
class Advice:
    profile: str  # "Classical" | "Hybrid" | "PQC-only"
    reason: str
    exposure_years: float  # x + y
    threat_years: float  # z
    at_risk: bool  # x + y > z


def advise(
    sensitivity: str,
    retention_years: float,
    migration_years: float = DEFAULT_MIGRATION_YEARS,
    threat_years: float = DEFAULT_THREAT_YEARS,
) -> Advice:
    """Return a protection profile and a plain-English reason."""
    if sensitivity not in SENSITIVITIES:
        raise ValueError(f"Sensitivity must be one of {SENSITIVITIES}, got {sensitivity!r}.")
    if retention_years <= 0 or migration_years < 0 or threat_years <= 0:
        raise ValueError("Retention and threat years must be positive; migration years cannot be negative.")

    exposure = retention_years + migration_years
    at_risk = exposure > threat_years
    numbers = f"{retention_years:g} + {migration_years:g} = {exposure:g} years vs {threat_years:g} assumed years to threat"

    if not at_risk:
        if sensitivity == "Critical":
            return Advice("Hybrid", f"Within the assumed timeline ({numbers}), but Critical data gets both locks as insurance.", exposure, threat_years, at_risk)
        return Advice("Classical", f"Safe within the assumed timeline ({numbers}).", exposure, threat_years, at_risk)

    if sensitivity == "Critical" and retention_years > threat_years:
        return Advice("PQC-only", f"Critical data outlives the threat date ({numbers}); a classical lock would add nothing by then.", exposure, threat_years, at_risk)
    return Advice("Hybrid", f"At risk of Harvest Now, Decrypt Later ({numbers}); keep the proven classical lock and add post-quantum.", exposure, threat_years, at_risk)
