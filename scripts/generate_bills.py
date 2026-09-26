#!/usr/bin/env python3
"""Generates one PDF bill per customer, baked into the image at build time
(app/bills/<meter_code>/<period>.pdf). Run from the Dockerfile, not at
container startup -- these never change per-instance.

Note on the library: the original plan called for fpdf2 (pure Python, no
system dependency), but this sandbox only has reportlab available to
actually test against, and shipping untested PDF-generation code wasn't a
trade worth making. reportlab is also pure Python for this kind of basic
canvas drawing -- no system binary dependency either -- so the "keep the
image lean" reasoning still holds.
"""
import os
import sys

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

sys.path.insert(0, os.path.dirname(__file__))
from fixtures import BILL_AMOUNTS, BILL_PERIOD, CUSTOMERS, METER_CODES, TRAVERSAL_FLAG_METER, TRAVERSAL_FLAG_VALUE

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
    for (email, password, name, service_addr, billing_addr), meter_code, amount in zip(
        CUSTOMERS, METER_CODES, BILL_AMOUNTS
    ):
        flag = TRAVERSAL_FLAG_VALUE if meter_code == TRAVERSAL_FLAG_METER else None
        path = os.path.join(OUT_DIR, meter_code, f"{BILL_PERIOD}.pdf")
        draw_bill(path, name, service_addr, meter_code, amount, flag)
        print(f"wrote {path}" + (" (flag)" if flag else ""))


if __name__ == "__main__":
    main()
