import requests


def test_plaintext_teach_toggle(plaintext_base_url, set_hardened):
    resp = requests.get(f"{plaintext_base_url}/login", allow_redirects=False, timeout=10)
    assert resp.status_code == 200

    set_hardened("PLAINTEXT_TEACH", True)

    resp = requests.get(f"{plaintext_base_url}/login", allow_redirects=False, timeout=10)
    assert resp.status_code == 308
    assert resp.headers.get("Location", "").startswith("https://")


def test_plaintext_exercise_toggle(plaintext_base_url, set_hardened, forge_none_alg_jwt_fn):
    token = forge_none_alg_jwt_fn("MTR-1001")
    resp = requests.post(
        f"{plaintext_base_url}/api/telemetry",
        json={"reading_kwh": 1.0},
        headers={"Authorization": f"Bearer {token}"},
        allow_redirects=False,
        timeout=10,
    )
    assert resp.status_code != 308

    set_hardened("PLAINTEXT_EXERCISE", True)

    resp = requests.post(
        f"{plaintext_base_url}/api/telemetry",
        json={"reading_kwh": 1.0},
        headers={"Authorization": f"Bearer {token}"},
        allow_redirects=False,
        timeout=10,
    )
    assert resp.status_code == 308
    assert resp.headers.get("Location", "").startswith("https://")
