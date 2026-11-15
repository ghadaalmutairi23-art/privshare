"""Generate synthetic students with Faker. Name, national ID and GPA are stored encrypted.

Run: python -m backend.data_gen [--n 500] [--gpa-scale 5] [--reset] [--seed 42]
The GPA scale defaults to GPA_SCALE from .env (4.0 if unset) and is saved with the data,
so the DP engine always clamps to the scale the data was generated with.
Only counts are printed - never individual records.
"""
import argparse
import random
import sqlite3
from contextlib import closing

from faker import Faker

from . import catalog, crypto, settings, student_store
from .config import db_path, gpa_scale_default
from .db import connect, init_db

# Major -> (mean GPA on a 4-point scale, cooperative-training completion probability)
MAJORS = {
    "Cybersecurity": (3.4, 0.80),
    "Computer Science": (3.3, 0.75),
    "Data Science": (3.2, 0.70),
    "Information Systems": (3.1, 0.65),
    "Software Engineering": (3.3, 0.72),
}
assert set(MAJORS) == set(catalog.MAJORS)
GRAD_YEARS = range(2020, 2026)
DEFAULT_N = 500
AAD_NAME, AAD_NATIONAL_ID, AAD_GPA = crypto.AAD_NAME, crypto.AAD_NATIONAL_ID, crypto.AAD_GPA


def gpa_bounds(scale: float) -> tuple[float, float]:
    """Lowest and highest generated GPA (a quarter of the scale is the floor)."""
    return scale / 4, scale


def seed(conn: sqlite3.Connection, n: int, key: bytes, rng_seed: int | None = None,
         gpa_scale: float = 4.0) -> int:
    """Insert n synthetic students and record the GPA scale. Returns the number inserted."""
    rng = random.Random(rng_seed)
    fake = Faker("ar_SA")
    if rng_seed is not None:
        fake.seed_instance(rng_seed)
    lo, hi = gpa_bounds(gpa_scale)
    factor = gpa_scale / 4.0

    used_ids: set[str] = set()
    student_nos = rng.sample(range(10_000, 100_000), n)  # unique "3xxxxx" numbers
    rows = []
    for i in range(n):
        major = rng.choice(list(MAJORS))
        mean_gpa, coop_p = MAJORS[major]
        gpa = round(min(hi, max(lo, rng.gauss(mean_gpa * factor, 0.45 * factor))), 2)
        national_id = "1" + "".join(rng.choices("0123456789", k=9))  # Saudi-style, 10 digits
        while national_id in used_ids:
            national_id = "1" + "".join(rng.choices("0123456789", k=9))
        used_ids.add(national_id)
        rows.append(student_store.encrypt_row({
            "student_no": f"3{student_nos[i]}", "name": fake.name(), "national_id": national_id,
            "major": major, "gpa": gpa, "grad_year": rng.choice(GRAD_YEARS),
            "coop_completed": rng.random() < coop_p,
        }, key))
    conn.executemany(student_store.INSERT_SQL, rows)
    settings.put(conn, settings.GPA_SCALE_KEY, str(gpa_scale))
    conn.commit()
    return len(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic (dummy) student data.")
    parser.add_argument("--n", type=int, default=DEFAULT_N, help="number of students (default 500)")
    parser.add_argument("--gpa-scale", type=float, default=None,
                        help="GPA scale, e.g. 4 or 5 (default: GPA_SCALE from .env, else 4)")
    parser.add_argument("--reset", action="store_true", help="delete existing students first")
    parser.add_argument("--seed", type=int, default=None, help="random seed for repeatable data")
    args = parser.parse_args(argv)
    if args.n < 1:
        parser.error("--n must be at least 1")
    scale = args.gpa_scale if args.gpa_scale is not None else gpa_scale_default()
    if not 1.0 <= scale <= 10.0:
        parser.error("--gpa-scale must be between 1 and 10")

    key = crypto.load_key()
    path = db_path()
    with closing(connect(path)) as conn:
        init_db(conn)
        existing = conn.execute("SELECT COUNT(*) FROM students").fetchone()[0]
        if existing and not args.reset:
            print(f"Database already has {existing} students. Use --reset to regenerate.")
            return 1
        if args.reset:
            conn.execute("DELETE FROM students")
        inserted = seed(conn, args.n, key, args.seed, scale)
    print(f"Inserted {inserted} synthetic students (GPA scale {scale:g}) into {path}"
          " (name, national ID and GPA encrypted).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
