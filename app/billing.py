"""
Request-time bill PDF generation -- specifically for Ben Osei's bill
(MTR-1002), the one that carries the TRAVERSAL_TEACH flag.

Every other customer's bill stays a plain static file baked in at image
build time by scripts/generate_bills.py, exactly as before -- there's
nothing to personalize about them. Ben's is the one exception: since
scripts/generate_bills.py runs once at Docker image build time, long
before any participant_id exists, a flag baked into that file at build
time could never be personalized. This module regenerates just that one
PDF in memory, at request time, with a flag computed for whoever's
asking -- see app/customer.py:download_bill().

Deliberately NOT imported by scripts/generate_bills.py, and vice versa --
scripts/ and app/ stay decoupled (see the existing duplication of small
fixture constants between scripts/fixtures.py and app/flags.py for the
same reason). This is a second, small copy of the same drawing code, not
a shared import.
"""
import io

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# Must match scripts/fixtures.py's CUSTOMERS[1] / METER_CODES[1] /
# BILL_AMOUNTS[1] and BILL_PERIOD exactly (Ben Osei, index 1) --
# duplicated here for the same reason the rest of these constants are.
BEN_NAME = "Ben Osei"
BEN_ADDRESS = "48 Oak Ave, Riverton"
BEN_METER_CODE = "MTR-1002"
BEN_BILL_AMOUNT = 38.90
BILL_PERIOD = "2026-09"


def draw_ben_bill_pdf(flag: str) -> bytes:
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, height - 72, "WattzGOAT")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 88, "Your monthly energy statement")

    c.setFont("Helvetica-Bold", 13)
    c.drawString(72, height - 130, f"Statement for {BILL_PERIOD}")
    c.setFont("Helvetica", 11)
    c.drawString(72, height - 150, BEN_NAME)
    c.drawString(72, height - 165, BEN_ADDRESS)
    c.drawString(72, height - 180, f"Meter: {BEN_METER_CODE}")

    c.line(72, height - 195, width - 72, height - 195)

    c.setFont("Helvetica", 11)
    c.drawString(72, height - 220, "Energy charges")
    c.drawRightString(width - 72, height - 220, f"${BEN_BILL_AMOUNT:.2f}")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 245, "Total due")
    c.drawRightString(width - 72, height - 245, f"${BEN_BILL_AMOUNT:.2f}")

    c.setFont("Helvetica", 8)
    c.setFillGray(0.6)
    c.drawString(72, 72, f"Security misconfiguration: {flag}")

    c.showPage()
    c.save()
    return buf.getvalue()
