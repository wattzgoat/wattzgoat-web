import secrets


def test_fileupload_teach_toggle(ops1_admin, base_url, set_hardened):
    resp = ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("update.bin", b"x" * 10)},
        timeout=10,
    )
    assert "FLAG{" in resp.text

    set_hardened("FILEUPLOAD_TEACH", True)

    resp = ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("update.exe", b"x" * 10)},
        timeout=10,
    )
    assert resp.status_code == 400
    resp = ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("update.bin", b"x" * (3 * 1024 * 1024))},
        timeout=10,
    )
    assert resp.status_code == 400


def test_fileupload_exercise_toggle(ops1_admin, base_url, set_hardened):
    before = ops1_admin.get(f"{base_url}/admin/firmware-canary", timeout=10).text

    set_hardened("FILEUPLOAD_EXERCISE", True)

    marker = f"PWNED_{secrets.token_hex(4)}"
    ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("../canary.txt", marker.encode())},
        timeout=10,
    )
    after = ops1_admin.get(f"{base_url}/admin/firmware-canary", timeout=10).text
    assert marker not in after
    assert after == before  # canary genuinely untouched, not just unchanged-looking
