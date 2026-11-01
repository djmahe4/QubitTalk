"""Smoke test: the Streamlit app renders every tab with real modules and no exceptions."""

from streamlit.testing.v1 import AppTest


def test_app_renders_all_tabs_without_errors():
    at = AppTest.from_file("../app.py", default_timeout=120).run()
    assert not at.exception
    assert len(at.tabs) == 5
    assert any("r = 4" in m.value for m in at.markdown)  # Qiskit lab ran (default base 7)
    assert at.metric[0].value == "7 vs 10 years"  # Mosca: 5 + 2 vs 10
