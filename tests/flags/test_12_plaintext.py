import jwt

PLAINTEXT_TEACH = "FLAG{OPEN_CHANNEL}"      # /login hidden field
PLAINTEXT_EXERCISE = "FLAG{LOUD_WHISPER}"   # /api/telemetry over the unencrypted port

# Matches app/devices.py's DEVICE_JWT_SECRET -- intentionally weak/guessable
# by design, not a real secret being leaked here.
DEVICE_JWT_SECRET = "wattzgoat-device-key"


def test_plaintext_teach_login_hidden_field(anon_session, base_url):
    resp = anon_session.get(f"{base_url}/login", timeout=10)
    assert resp.status_code == 200
    assert PLAINTEXT_TEACH in resp.text


def test_plaintext_exercise_telemetry(anon_session, plaintext_base_url):
    token = jwt.encode({"meter_code": "MTR-1001"}, DEVICE_JWT_SECRET, algorithm="HS256")
    resp = anon_session.post(
        f"{plaintext_base_url}/api/telemetry",
        headers={"Authorization": f"Bearer {token}"},
        json={"reading_kwh": 2.5},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.json().get("plaintext_flag") == PLAINTEXT_EXERCISE
