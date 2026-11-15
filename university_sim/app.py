"""Simulated university information system (SIS).

A separate Flask service that plays the university's student system. It generates synthetic
students with Faker (deterministic for a given seed) and serves them over an API-key
protected, paginated endpoint that PrivShare's "Sync" pulls from:

    GET /api/students?page=1      header  X-API-Key: <SIS_API_KEY>

A few deliberately invalid rows (SIS_BAD_ROWS) show PrivShare's rejection report.

Run: python -m university_sim.app      -> https://127.0.0.1:5001 (uses certs/ if present)
"""
import hmac
import os
import random
from pathlib import Path

from dotenv import load_dotenv
from faker import Faker
from flask import Flask, abort, jsonify, request

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

MAJORS = ["Computer Science", "Cybersecurity", "Data Science", "Information Systems", "Software Engineering"]
PER_PAGE = 100


def generate_students(n: int, seed: int, gpa_scale: float, bad_rows: int) -> list[dict]:
    """Synthetic students as the SIS would export them (plain fields; PrivShare encrypts on arrival)."""
    rng = random.Random(seed)
    fake = Faker("ar_SA")
    fake.seed_instance(seed)
    factor = gpa_scale / 4.0
    used_ids, students = set(), []
    for i in range(n):
        national_id = "1" + "".join(rng.choices("0123456789", k=9))
        while national_id in used_ids:
            national_id = "1" + "".join(rng.choices("0123456789", k=9))
        used_ids.add(national_id)
        gpa = min(gpa_scale, max(gpa_scale / 4, rng.gauss(3.3 * factor, 0.45 * factor)))
        students.append({
            "student_no": f"4{20000 + i:05d}",
            "name": fake.name(),
            "national_id": national_id,
            "major": rng.choice(MAJORS),
            "gpa": round(gpa, 2),
            "grad_year": rng.randint(2020, 2025),
            "coop_completed": rng.random() < 0.72,
        })
    # Deliberately broken records, as real exports sometimes contain
    for j in range(min(bad_rows, n)):
        bad = students[(j * 37) % n]
        if j % 2 == 0:
            bad["gpa"] = round(gpa_scale + 0.6, 2)          # above the scale
        else:
            bad["national_id"] = bad["national_id"][:9]     # 9 digits
    return students


def create_app(api_key: str | None = None, n: int | None = None, seed: int | None = None,
               gpa_scale: float | None = None, bad_rows: int | None = None) -> Flask:
    api_key = api_key if api_key is not None else os.environ.get("SIS_API_KEY", "")
    if len(api_key) < 16:
        raise RuntimeError("SIS_API_KEY must be set (at least 16 characters)")
    students = generate_students(
        n if n is not None else int(os.environ.get("SIS_STUDENTS", "520")),
        seed if seed is not None else int(os.environ.get("SIS_SEED", "42")),
        gpa_scale if gpa_scale is not None else float(os.environ.get("GPA_SCALE", "4")),
        bad_rows if bad_rows is not None else int(os.environ.get("SIS_BAD_ROWS", "2")),
    )
    app = Flask(__name__)

    @app.before_request
    def check_key():
        if request.path.startswith("/api/students"):
            given = request.headers.get("X-API-Key", "")
            if not hmac.compare_digest(given.encode(), api_key.encode()):
                abort(401)

    @app.get("/api/students")
    def list_students():
        page = request.args.get("page", "1")
        if not page.isdigit() or int(page) < 1:
            abort(400)
        start = (int(page) - 1) * PER_PAGE
        return jsonify(page=int(page), per_page=PER_PAGE, total=len(students),
                       students=students[start:start + PER_PAGE])

    @app.get("/api/health")
    def health():
        return jsonify(status="ok")

    @app.errorhandler(400)
    @app.errorhandler(401)
    @app.errorhandler(404)
    def error(exc):
        return jsonify(error=exc.name), exc.code

    return app


def main() -> None:
    app = create_app()
    cert, key = ROOT / "certs" / "cert.pem", ROOT / "certs" / "key.pem"
    ssl_context = (str(cert), str(key)) if cert.exists() and key.exists() else None
    app.run(host="127.0.0.1", port=int(os.environ.get("SIS_PORT", "5001")), ssl_context=ssl_context)


if __name__ == "__main__":
    main()
