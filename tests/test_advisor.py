import pytest

from src.advisor import advise


def test_short_retention_is_classical():
    a = advise("Medium", 3)
    assert (a.profile, a.at_risk) == ("Classical", False)


def test_long_retention_is_hybrid():
    a = advise("High", 5, threat_years=6)
    assert (a.profile, a.at_risk) == ("Hybrid", True)
    assert "Harvest Now" in a.reason


def test_boundary_exactly_at_threat_is_not_at_risk():
    # Mosca: at risk only when x + y > z, so equality is still safe.
    assert advise("Low", 8, migration_years=2, threat_years=10).at_risk is False
    assert advise("Low", 8.1, migration_years=2, threat_years=10).at_risk is True


def test_critical_gets_hybrid_insurance_even_when_safe():
    assert advise("Critical", 1).profile == "Hybrid"


def test_critical_outliving_threat_is_pqc_only():
    assert advise("Critical", 15).profile == "PQC-only"


def test_assumptions_appear_in_reason():
    assert "10 assumed years" in advise("Low", 1).reason


@pytest.mark.parametrize("args", [("Extreme", 5), ("High", 0), ("High", -1)])
def test_invalid_input_rejected(args):
    with pytest.raises(ValueError):
        advise(*args)
