"""Generates a customer's bill PDF on request."""
import io

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

BEN_NAME = "Ben Wood"
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
