def test_traversal_teach_toggle(devon, base_url, set_hardened):
    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("application/pdf")

    set_hardened("TRAVERSAL_TEACH", True)

    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 403

    # Full escape attempt, still blocked.
    resp = devon.get(f"{base_url}/bills/download", params={"path": "../../../../etc/passwd"}, timeout=10)
    assert resp.status_code == 403

    # Own bill still works.
    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 200


def test_cmdinject_exercise_toggle(ops1_admin, base_url, set_hardened):
    marker = "CMDINJECT_PROOF_MARKER"
    resp = ops1_admin.post(f"{base_url}/admin/diagnostics", data={"host": f"127.0.0.1; echo {marker}"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("CMDINJECT_EXERCISE", True)

    resp = ops1_admin.post(f"{base_url}/admin/diagnostics", data={"host": f"127.0.0.1; echo {marker}"}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text

    output_start = resp.text.find("<pre")
    output_text = resp.text[output_start:]
    bare_lines = [line.strip() for line in output_text.splitlines()]
    assert marker not in bare_lines  # no line is JUST the marker by itself
    assert "Name or service not known" in output_text or "ping" in output_text.lower()
