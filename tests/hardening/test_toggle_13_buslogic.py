def test_buslogic_teach_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_TEACH", True)

    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert "FLAG{" not in resp.text


def test_buslogic_exercise_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_EXERCISE", True)

    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert "FLAG{" not in resp.text


def test_buslogic_negative_recharge_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "-5"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_NEGATIVE_RECHARGE", True)

    # The real fix: zero and negative amounts are rejected, not just unflagged.
    for bad in ("-5", "0", "nan"):
        resp = alice.post(f"{base_url}/recharge", data={"amount_paid": bad}, timeout=10)
        assert resp.status_code == 400, bad
        assert "FLAG{" not in resp.text
        assert "greater than $0.00" in resp.text

    # A normal recharge still works.
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10"}, timeout=10)
    assert resp.status_code == 200
    assert "kWh added" in resp.text


def test_buslogic_negative_solar_toggle(alice, base_url, set_hardened):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "-10"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("BUSLOGIC_NEGATIVE_SOLAR", True)

    for bad in ("-10", "0"):
        resp = alice.post(f"{base_url}/solar", data={"exported_kwh": bad}, timeout=10)
        assert resp.status_code == 400, bad
        assert "FLAG{" not in resp.text

    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "10"}, timeout=10)
    assert resp.status_code == 200
    assert "kWh added" in resp.text

