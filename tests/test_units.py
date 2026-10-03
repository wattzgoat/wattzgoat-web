"""Conversions between dollars and kWh on the recharge and solar pages."""
import re


def _balance(session, base_url):
    html = session.get(f"{base_url}/recharge", timeout=10).text
    m = re.search(r"current balance ([\d,]+\.\d\d) kWh", html)
    assert m, "recharge page should show the balance in kWh"
    return float(m.group(1).replace(",", ""))


def test_recharge_converts_dollars_to_kwh(alice, base_url):
    before = _balance(alice, base_url)
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "28"}, timeout=10)
    assert resp.status_code == 200
    assert "You paid $28.00" in resp.text
    assert "100.00 kWh added" in resp.text            # 28 / 0.28
    assert abs(_balance(alice, base_url) - (before + 100.0)) < 0.01


def test_recharge_page_states_the_rate(alice, base_url):
    html = alice.get(f"{base_url}/recharge", timeout=10).text
    assert "$0.28 per kWh" in html
    assert "Amount to pay ($)" in html


def test_dashboard_balance_is_in_kwh(alice, base_url):
    html = alice.get(f"{base_url}/dashboard", timeout=10).text
    assert "prepaid energy balance" in html
    assert "kWh</span>" in html


def test_solar_credit_is_converted_to_kwh(alice, base_url):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "100"}, timeout=10)
    assert resp.status_code == 200
    assert "$12.00 credit" in resp.text                # 100 * 0.12
    assert "42.86 kWh added" in resp.text              # 12 / 0.28
