"""Blank import templates (header + two clearly fictional example rows) as CSV and Excel bytes."""
import csv
import io

from openpyxl import Workbook
from openpyxl.styles import Font

from .ingest import COLUMNS

EXAMPLE_ROWS = [
    ["400001", "Example Student One", "1000000001", "Cybersecurity", "3.45", "2025", "yes"],
    ["400002", "Example Student Two", "2000000002", "Computer Science", "2.90", "2024", "no"],
]


def csv_bytes() -> bytes:
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(COLUMNS)
    writer.writerows(EXAMPLE_ROWS)
    return ("﻿" + out.getvalue()).encode("utf-8")  # BOM so Excel opens it as UTF-8


def xlsx_bytes() -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "students"
    ws.append(list(COLUMNS))
    for row in EXAMPLE_ROWS:
        ws.append(row)
    for cell in ws[1]:
        cell.font = Font(bold=True)
    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()
