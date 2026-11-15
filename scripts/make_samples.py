"""Write the import templates to samples/sample_students.csv and .xlsx (same files the API serves).

Run: python scripts/make_samples.py
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from backend import import_templates  # noqa: E402


def main() -> int:
    out = ROOT / "samples"
    out.mkdir(exist_ok=True)
    (out / "sample_students.csv").write_bytes(import_templates.csv_bytes())
    (out / "sample_students.xlsx").write_bytes(import_templates.xlsx_bytes())
    print(f"Wrote {out / 'sample_students.csv'} and {out / 'sample_students.xlsx'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
