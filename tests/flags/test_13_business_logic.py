def test_buslogic_teach_recharge(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "10", "units_credited": "99999"}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_buslogic_exercise_solar(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "5000"}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_buslogic_negative_recharge(alice, base_url, extract_flag_fn, redeem_flag_fn):
    # No lower bound on the payment: a negative amount is applied as-is.
    resp = alice.post(f"{base_url}/recharge", data={"amount_paid": "-5"}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_buslogic_negative_solar(alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = alice.post(f"{base_url}/solar", data={"exported_kwh": "-10"}, timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)

