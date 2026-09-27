import secrets


import secrets

import requests


def test_rxss_exercise_toggle(base_url, set_hardened):
    payload = "<script>alert(document.title)</script>@test.com"
    resp = requests.post(f"{base_url}/forgot-password", data={"email": payload}, verify=False, timeout=10)
    assert payload in resp.text

    set_hardened("RXSS_EXERCISE", True)

    resp = requests.post(f"{base_url}/forgot-password", data={"email": payload}, verify=False, timeout=10)
    assert payload not in resp.text
    assert "&lt;script&gt;" in resp.text


def test_sxss_teach_toggle(alice, base_url, set_hardened):
    marker = f"<script>alert({secrets.token_hex(4)})</script>"
    alice.post(f"{base_url}/meters/1/nickname", data={"nickname": marker}, timeout=10)
    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    assert marker in resp.text

    set_hardened("SXSS_TEACH", True)

    resp = alice.get(f"{base_url}/dashboard", timeout=10)
    assert marker not in resp.text
    assert "&lt;script&gt;" in resp.text

    # Restore a harmless nickname so this doesn't leak a raw <script> tag
    # into later tests/flags/ runs against the same live instance.
    set_hardened("SXSS_TEACH", False)
    alice.post(f"{base_url}/meters/1/nickname", data={"nickname": "My meter"}, timeout=10)


def test_sxss_exercise_toggle(alice, ops1_admin, base_url, set_hardened):
    marker = f"<script>alert({secrets.token_hex(4)})</script>"
    alice.post(
        f"{base_url}/support",
        data={"subject": marker, "description": "normal description"},
        timeout=10,
    )
    resp = ops1_admin.get(f"{base_url}/admin/tickets", timeout=10)
    assert marker in resp.text

    set_hardened("SXSS_EXERCISE", True)

    resp = ops1_admin.get(f"{base_url}/admin/tickets", timeout=10)
    assert marker not in resp.text
    assert "&lt;script&gt;" in resp.text
