"""Spreadsheet-formula safety for the CSV export (app/export.py:safe_cell).
Needs the app package importable (Flask installed); skipped otherwise."""
import importlib.util
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("flask") is None, reason="Flask not installed here, so the app package can't be imported")


def _safe_cell():
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from app.export import safe_cell

    return safe_cell


def test_text_that_could_be_a_formula_is_neutralized():
    safe_cell = _safe_cell()
    for risky in ("=1+1", "+1", "-Spark", "@SUM(A1)", "\tcmd", "\rcmd"):
        assert safe_cell(risky) == "'" + risky


def test_ordinary_values_are_untouched():
    safe_cell = _safe_cell()
    assert safe_cell("Circuit Breaker") == "Circuit Breaker"
    assert safe_cell("a,b") == "a,b"
    assert safe_cell("2026-10-02 11:15:48") == "2026-10-02 11:15:48"
    assert safe_cell(5) == 5
    assert safe_cell(None) == ""
