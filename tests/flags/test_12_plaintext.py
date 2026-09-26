import jwt

# Matches app/devices.py's DEVICE_JWT_SECRET -- intentionally weak/guessable
# by design, not a real secret being leaked here.
DEVICE_JWT_SECRET = "wattzgoat-device-key"


def test_plaintext_teach_login_hidden_field(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)


def test_plaintext_exercise_telemetry(anon_session, alice, base_url, plaintext_base_url, redeem_flag_fn):
    token = jwt.encode({"meter_code": "MTR-1001"}, DEVICE_JWT_SECRET, algorithm="HS256")
    resp = anon_session.post(
        f"{plaintext_base_url}/api/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json={"reading_kwh": 2.5},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = resp.json().get("plaintext_flag")
    assert flag
    assert redeem_flag_fn(alice, base_url, flag)
