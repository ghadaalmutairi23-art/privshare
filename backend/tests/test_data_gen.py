from contextlib import closing

from backend import crypto, data_gen, settings
from backend.db import connect, init_db


def _seeded(tmp_path, n=500):
    conn = connect(str(tmp_path / "students.db"))
    init_db(conn)
    data_gen.seed(conn, n, crypto.load_key(), rng_seed=1)
    return conn


def test_at_least_500_students(tmp_path):
    with closing(_seeded(tmp_path)) as conn:
        assert conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] >= 500
        majors = {r[0] for r in conn.execute("SELECT DISTINCT major FROM students")}
        assert majors == set(data_gen.MAJORS)


def test_sensitive_fields_are_encrypted_and_decryptable(tmp_path):
    key = crypto.load_key()
    with closing(_seeded(tmp_path)) as conn:
        rows = conn.execute("SELECT name_enc, national_id_enc, gpa_enc FROM students").fetchall()
    for name_enc, nid_enc, gpa_enc in rows:
        # Stored values are ciphertext, not the plain value
        assert not (nid_enc.isdigit() and len(nid_enc) == 10)
        gpa = crypto.decrypt(gpa_enc, key, data_gen.AAD_GPA)
        lo, hi = data_gen.gpa_bounds(4.0)
        assert gpa != gpa_enc and lo <= float(gpa) <= hi
        nid = crypto.decrypt(nid_enc, key, data_gen.AAD_NATIONAL_ID)
        assert nid.isdigit() and len(nid) == 10
        assert crypto.decrypt(name_enc, key, data_gen.AAD_NAME) != name_enc


def test_national_ids_are_unique(tmp_path):
    key = crypto.load_key()
    with closing(_seeded(tmp_path)) as conn:
        ids = [crypto.decrypt(r[0], key, data_gen.AAD_NATIONAL_ID)
               for r in conn.execute("SELECT national_id_enc FROM students")]
    assert len(ids) == len(set(ids))


def test_cli_prints_counts_only(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DB_PATH", str(tmp_path / "cli.db"))
    assert data_gen.main(["--n", "50", "--seed", "7"]) == 0
    out = capsys.readouterr().out
    assert "Inserted 50" in out

    key = crypto.load_key()
    with closing(connect(str(tmp_path / "cli.db"))) as conn:
        names = [crypto.decrypt(r[0], key, data_gen.AAD_NAME) for r in conn.execute("SELECT name_enc FROM students")]
    assert not any(name in out for name in names)

    # A second run without --reset refuses to add duplicates
    assert data_gen.main(["--n", "50"]) == 1


def test_gpa_scale_option_is_saved_with_the_data(tmp_path, monkeypatch, client, accounts):
    from .conftest import login
    monkeypatch.setenv("DB_PATH", str(tmp_path / "scale.db"))
    assert data_gen.main(["--n", "300", "--gpa-scale", "5", "--seed", "2"]) == 0

    key = crypto.load_key()
    with closing(connect(str(tmp_path / "scale.db"))) as conn:
        assert settings.get(conn, settings.GPA_SCALE_KEY) == "5.0"
        gpas = [float(crypto.decrypt(r[0], key, data_gen.AAD_GPA)) for r in conn.execute("SELECT gpa_enc FROM students")]
    assert max(gpas) <= 5.0 and max(gpas) > 4.0      # really on a 5-point scale

    # --reset with a different scale replaces the setting
    monkeypatch.setenv("GPA_SCALE", "4")
    assert data_gen.main(["--n", "50", "--reset"]) == 0
    with closing(connect(str(tmp_path / "scale.db"))) as conn:
        assert settings.get(conn, settings.GPA_SCALE_KEY) == "4.0"


def test_api_uses_the_saved_scale(app, client, accounts):
    from backend.db import get_db
    from .conftest import login
    with app.app_context():
        data_gen.seed(get_db(), 50, crypto.load_key(), rng_seed=1, gpa_scale=5.0)
    login(client, accounts["analyst"])
    assert client.get("/api/query/options").get_json()["gpa_scale"] == 5.0


def test_invalid_scale_refused(tmp_path, monkeypatch):
    import pytest
    monkeypatch.setenv("DB_PATH", str(tmp_path / "bad.db"))
    with pytest.raises(SystemExit):
        data_gen.main(["--gpa-scale", "0"])


def test_old_database_is_upgraded_in_place(tmp_path):
    """A students table from Phase 1/2 (no student number columns) keeps its rows and gains the columns."""
    import sqlite3
    path = str(tmp_path / "old.db")
    old = sqlite3.connect(path)
    old.execute("CREATE TABLE students (id INTEGER PRIMARY KEY, name_enc TEXT NOT NULL, national_id_enc TEXT NOT NULL,"
                " gpa_enc TEXT NOT NULL, major TEXT NOT NULL, grad_year INTEGER NOT NULL, coop_completed INTEGER NOT NULL)")
    old.execute("INSERT INTO students VALUES (1, 'a', 'b', 'c', 'Cybersecurity', 2024, 1)")
    old.commit()
    old.close()
    with closing(connect(path)) as conn:
        init_db(conn)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(students)")}
        assert {"student_no_enc", "student_no_hash"} <= cols
        assert conn.execute("SELECT COUNT(*) FROM students").fetchone()[0] == 1
