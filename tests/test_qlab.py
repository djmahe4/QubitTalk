import pytest

from src.qlab import find_order


def test_order_of_7_mod_15_is_4_and_factors_found():
    r = find_order(7, 15)
    assert r.order == 4
    assert r.factors == (3, 5)


def test_peaks_are_multiples_of_quarter_of_register():
    # With 3 counting qubits and r = 4, phases are k/4, so counts sit at 0, 2, 4, 6.
    assert set(find_order(7, 15, counting=3).counts) <= {0, 2, 4, 6}


def test_other_base_has_order_2():
    r = find_order(4, 15)  # 4^2 = 16 = 1 mod 15
    assert r.order == 2


def test_rejects_unsupported_input():
    with pytest.raises(ValueError):
        find_order(5, 15)  # shares a factor with 15
    with pytest.raises(ValueError):
        find_order(7, 21)
