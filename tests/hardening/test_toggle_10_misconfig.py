def test_traversal_teach_toggle(devon, base_url, set_hardened):
    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 200
    assert resp.headers.get("content-type", "").startswith("application/pdf")

    set_hardened("TRAVERSAL_TEACH", True)

    # Sibling-folder access (the actual documented exploit) -- never
    # leaves BILLS_DIR, so containment alone wouldn't catch this; the
    # hardened branch checks ownership of the meter-code segment too.
    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 403

    # Full escape attempt, still blocked.
    resp = devon.get(f"{base_url}/bills/download", params={"path": "../../../../etc/passwd"}, timeout=10)
    assert resp.status_code == 403

    # Own bill still works.
    resp = devon.get(f"{base_url}/bills/download", params={"path": "MTR-1004/2026-09.pdf"}, timeout=10)
    assert resp.status_code == 200


def test_cmdinject_exercise_toggle(ops1_admin, base_url, set_hardened):
    resp = ops1_admin.post(f"{base_url}/admin/diagnostics", data={"host": "127.0.0.1; echo CMDINJECT_PROOF_MARKER"}, timeout=10)
    assert "FLAG{" in resp.text

    set_hardened("CMDINJECT_EXERCISE", True)

    resp = ops1_admin.post(f"{base_url}/admin/diagnostics", data={"host": "127.0.0.1; echo CMDINJECT_PROOF_MARKER"}, timeout=10)
    assert resp.status_code == 200
    assert "FLAG{" not in resp.text
    # The injected command's OWN OUTPUT never appears in the <pre> block
    # (the semicolon-echoed value in the input's `value=` attribute is
    # expected and harmless -- that's just the form re-showing what was
    # submitted, not proof of execution).
    output_start = resp.text.find("<pre")
    assert "CMDINJECT_PROOF_MARKER" not in resp.text[output_start:]
