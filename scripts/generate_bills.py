#!/usr/bin/env python3
"""Generates one PDF bill per customer, at image build time."""
import os
import sys

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

sys.path.insert(0, os.path.dirname(__file__))
from fixtures import BILL_AMOUNTS, BILL_PERIOD, CUSTOMERS, METER_CODES, TRAVERSAL_FLAG_METER

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "app", "bills")


def draw_bill(path: str, name: str, address: str, meter_code: str, amount: float, flag: str | None) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    c = canvas.Canvas(path, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 18)
    c.drawString(72, height - 72, "WattzGOAT")
    c.setFont("Helvetica", 10)
    c.drawString(72, height - 88, "Your monthly energy statement")

    c.setFont("Helvetica-Bold", 13)
    c.drawString(72, height - 130, f"Statement for {BILL_PERIOD}")
    c.setFont("Helvetica", 11)
    c.drawString(72, height - 150, name)
    c.drawString(72, height - 165, address)
    c.drawString(72, height - 180, f"Meter: {meter_code}")

    c.line(72, height - 195, width - 72, height - 195)

    c.setFont("Helvetica", 11)
    c.drawString(72, height - 220, "Energy charges")
    c.drawRightString(width - 72, height - 220, f"${amount:.2f}")
    c.setFont("Helvetica-Bold", 12)
    c.drawString(72, height - 245, "Total due")
    c.drawRightString(width - 72, height - 245, f"${amount:.2f}")

    if flag:
        c.setFont("Helvetica", 8)
        c.setFillGray(0.6)
        c.drawString(72, 72, f"Security misconfiguration teach instance: {flag}")

    c.showPage()
    c.save()


def main() -> None:
    for (_email, _password, name, service_addr, _billing_addr), meter_code, amount in zip(
        CUSTOMERS, METER_CODES, BILL_AMOUNTS
    ):
        path = os.path.join(OUT_DIR, meter_code, f"{BILL_PERIOD}.pdf")
        draw_bill(path, name, service_addr, meter_code, amount, flag=None)
        print(f"wrote {path}" + (" (flag account, regenerated per-request)" if meter_code == TRAVERSAL_FLAG_METER else ""))


if __name__ == "__main__":
    main()
