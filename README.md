# PrivShare

Privacy-preserving sharing of university student statistics with labor-market entities
(graduation project, Cyber Security Program, Qassim University). See `CLAUDE.md` for the design.

**Status: Phase 1b done (Phases 1, 1b, 2 complete; 2.5 UI design published)**
- Phase 1: Flask JSON API with encrypted SQLite storage, synthetic data, Argon2 + TOTP login,
  RBAC for 5 roles, CSRF, rate limiting, 15-minute idle timeout (server-side sessions), HTTPS.
- Phase 1b: simulated university information system + sync, CSV/Excel import with a rejection
  report, the owner's student-record view, per-analyst permissions and budgets set by the owner.
- Phase 2: OpenDP Laplace engine, persistent privacy budget, k = 10 check, dual-party approval of
  query types, and the full query pipeline with a **stub** chain client (the real contract is Phase 3).

## Setup (Windows PowerShell)

```powershell
cd privshare
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt

python scripts\gen_secrets.py --write   # creates .env with DATA_KEY, SECRET_KEY, SIS_API_KEY
                                        # (existing .env from an earlier phase? use --add-missing)
python scripts\make_cert.py             # self-signed certs\cert.pem + key.pem
python -m backend.seed_users            # one demo user per role; prints password + TOTP key ONCE
```

Add each printed TOTP key to an authenticator app (Google/Microsoft Authenticator: "enter a setup key").
Lost them? `python -m backend.seed_users --reset` issues new ones.

> Keep `.env` safe: if `DATA_KEY` is lost or changed, the encrypted data can't be read anymore.

### Getting student data in (pick one)

1. **Sync from the simulated university system** (the realistic path):
   start `python -m university_sim.app` (https://127.0.0.1:5001), sign in as `uni_owner1`, then
   `POST /api/owner/sync`. It pulls every page with the API key, validates, encrypts and upserts
   by student number. A couple of deliberately broken records show up in the rejection report.
2. **Import a file:** `POST /api/owner/import` with a `.csv` or `.xlsx` (max 5 MB).
   Templates: `samples/sample_students.csv` / `.xlsx`, or `GET /api/owner/import/template.csv|xlsx`.
3. **Quick seed for development:** `python -m backend.data_gen` (500 synthetic students).

Uploaded files are parsed in memory and never written to disk. Sensitive fields (student number,
name, national ID, GPA) are stored with AES-256-GCM; student numbers also get a keyed HMAC index
so a re-import updates the same student instead of creating a duplicate.

### GPA scale (4 or 5)

The scale is a setting: `GPA_SCALE` in `.env` (default 4) or `--gpa-scale` on `data_gen`.
It is **saved in the database together with the data**. Imports reject GPAs above the saved scale,
and the DP engine always clamps to it, so the setting and the data can never disagree.

## Run

```powershell
python -m university_sim.app             # terminal 1 - simulated university system, port 5001
python -m backend.app                    # terminal 2 - PrivShare API, https://127.0.0.1:5000
```

Use `127.0.0.1` rather than `localhost` for scripts: on Windows `localhost` tries IPv6 first
and adds about 2 seconds to every request.

## Test

```powershell
pytest -v                                # automated tests (temporary DB and keys, never touches .env)
python scripts\smoke_login.py analyst1   # manual check against the running server
```

## API

All POST/PUT/PATCH requests need the header `X-CSRFToken` (from `/api/auth/csrf`, `/login` or `/mfa`).
JSON bodies are limited to 64 KB; only the file import accepts up to 5 MB.

| Method | Path | Who | Purpose |
|---|---|---|---|
| GET | `/api/health` | anyone | liveness |
| GET | `/api/auth/csrf` | anyone | get a CSRF token |
| POST | `/api/auth/login` | anyone | `{username, password}` -> step 1 (5/min per IP) |
| POST | `/api/auth/mfa` | after step 1 | `{code}` -> logged in (5/min per IP) |
| POST | `/api/auth/logout` | logged in | end session |
| GET | `/api/auth/me` | logged in | username, role, permissions |
| GET | `/api/admin/users` | admin | list users (analyst budgets shown read-only) |
| POST | `/api/admin/users` | admin | `{username, password, role}` -> returns TOTP URI once |
| PATCH | `/api/admin/users/<id>` | admin | `{role}` and/or `{active}` |
| POST | `/api/owner/sync` | uni_owner | pull students from the university system |
| POST | `/api/owner/import` | uni_owner | multipart `file` (.csv/.xlsx) -> import report |
| GET | `/api/owner/import/template.csv` / `.xlsx` | uni_owner | blank templates |
| GET | `/api/owner/imports` | uni_owner | import history + number of students |
| GET | `/api/owner/students?page&per_page&q&major&grad_year` | **uni_owner only** | decrypted records (national ID masked); every view logged |
| GET | `/api/owner/students/<id>/national-id` | **uni_owner only** | reveal one national ID (logged) |
| GET | `/api/owner/analysts` | uni_owner | analysts with permissions and budgets |
| PUT | `/api/owner/analysts/<id>/permissions` | uni_owner | `{query_types, majors, years, max_queries}` (empty list = all) |
| PATCH | `/api/owner/analysts/<id>/budget` | uni_owner | `{epsilon_total}`; spent ε is never reset |
| GET | `/api/approvals/query-types` | owner, partner, analyst, auditor | approval status of each query type |
| POST | `/api/approvals/query-types/<name>/approve` | uni_owner / partner_rep | approve for your side |
| POST | `/api/approvals/query-types/<name>/revoke` | uni_owner / partner_rep | withdraw your side's approval |
| GET | `/api/query/options` | analyst | query types and filter values **within your permissions**, ε range, GPA scale |
| GET | `/api/query/permissions` | analyst | your own permissions and budget |
| GET | `/api/query/budget` | analyst | total / spent / remaining ε |
| POST | `/api/query` | analyst | run a query (30/min) |

Query body: `{"query_type": "avg_gpa", "filters": {"major": "Cybersecurity", "grad_year": 2024}, "epsilon": 0.5}`

Refusals, in pipeline order: `403 ... not approved ...`, `403 Outside your permissions`,
`403 Query rejected by privacy policy` (group < 10), `403 Privacy budget exhausted`,
`503 Audit service unavailable` (fail closed). If an analyst is limited to some majors (or years),
every query must filter on one of them - a query over "all" would include groups they may not use.

## Sessions

Login sessions are stored server-side (`sessions` table). The cookie carries only a random
token, and the table stores its SHA-256. Logout, deactivation and the 15-minute idle timeout
delete the row, so a copied or replayed cookie stops working.

## Differential privacy

The model (what is protected, how noise is calibrated, measured accuracy, and why the mean
uses a bounded model) is in [docs/dp_model.md](docs/dp_model.md).

## Layout

```
backend/        app.py config.py db.py crypto.py auth.py users.py roles.py rbac.py security.py
                events.py sessions.py settings.py catalog.py data_gen.py seed_users.py
                student_store.py ingest.py import_templates.py sis_client.py permissions.py
                dp.py budget.py analytics.py audit.py chain.py routes/ tests/
university_sim/ simulated university information system (separate Flask service)
samples/        sample_students.csv / .xlsx import templates
scripts/        gen_secrets.py make_cert.py make_samples.py smoke_login.py
docs/           dp_model.md
```
