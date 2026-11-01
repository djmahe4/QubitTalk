from crypto.password import PasswordAnalysis, analyze_password_strength


def test_empty_password():
    res = analyze_password_strength("")
    assert res.level == "Weak"
    assert res.score == 0
    assert not res.passed_min_length


def test_short_password():
    res = analyze_password_strength("abc")
    assert res.level == "Weak"
    assert not res.passed_min_length


def test_medium_password():
    # 8-11 characters with decent mix
    res = analyze_password_strength("Abc12345")
    assert res.level == "Medium"
    assert res.score >= 40
    assert res.passed_min_length


def test_hard_password():
    # 12+ characters with uppercase, lowercase, numbers, symbols
    res = analyze_password_strength("Tr0ub4dor&3#PostQuantum")
    assert res.level == "Hard"
    assert res.score >= 80
    assert res.entropy_bits > 60


def test_common_pattern_penalty():
    # Common dictionary / sequential pattern
    res = analyze_password_strength("password123")
    assert res.level in ("Weak", "Medium")
    # Much weaker than a random password of same length
    random_res = analyze_password_strength("k9#Xm!2pQv9$")
    assert res.score < random_res.score


def test_analysis_structure():
    res = analyze_password_strength("SecretKey123!")
    assert isinstance(res, PasswordAnalysis)
    assert res.level in ("Weak", "Medium", "Hard")
    assert 0 <= res.score <= 100
    assert res.classical_crack_time != ""
    assert res.quantum_crack_time != ""
