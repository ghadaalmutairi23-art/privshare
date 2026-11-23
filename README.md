# PrivShare

Privacy-preserving sharing of university student statistics with labor-market entities
(graduation project, Cyber Security Program, Qassim University). See `CLAUDE.md` for the design.

**Status: Phase 4 done (Phases 1, 1b, 2, 2.5, 3 and 4 complete; next: the React dashboard)**
- Phase 1: Flask JSON API with encrypted SQLite storage, synthetic data, Argon2 + TOTP login,
  RBAC for 5 roles, CSRF, rate limiting, 15-minute idle timeout (server-side sessions), HTTPS.
- Phase 1b: simulated university information system + sync, CSV/Excel import with a rejection
  report, the owner's student-record view, per-analyst permissions and budgets set by the owner.
- Phase 2: OpenDP Laplace engine, persistent privacy budget, k = 10 check, dual-party approval of
  query types, and the full query pipeline.
- Phase 3: Solidity contract `PrivShareAudit` on a local **Anvil** node (state saved to disk),
  web3.py client, auditor log + integrity verification, fail closed when the node is down.
- Phase 4: anomaly detection (Isolation Forest + a far-beyond-normal check) re-scores each analyst
  after every query; explainable alerts for the admin; attack simulation script.

## Setup (Windows, VS Code terminal)

```powershell
python -m venv venv
venv/Scripts/activate
pip install -r backend\requirements.txt

python scripts\gen_secrets.py --write   # creates .env with DATA_KEY, SECRET_KEY, SIS_API_KEY
                                        # (existing .env from an earlier phase? use --add-missing)
python scripts\make_cert.py             # self-signed certs\cert.pem + key.pem
python scripts\get_anvil.py             # downloads Anvil (pinned version, checksum verified) into tools\
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
python scripts\run_chain.py              # terminal 1 - local blockchain (Anvil), 127.0.0.1:8545
python contracts\deploy.py               # once, in another terminal - deploys the contract
python -m university_sim.app             # terminal 2 - simulated university system, port 5001
python -m backend.app                    # terminal 3 - PrivShare API, https://127.0.0.1:5000
```

`run_chain.py` saves the chain to `chain/anvil-state.json` every few seconds and reloads it on
start, so the contract, approvals and logged fingerprints survive restarts. `deploy.py` does
nothing if a contract is already live; `--force` deploys a new one (older audit records will then
show as `not_on_chain`, because they were logged on the previous contract).

### Blockchain in one paragraph

`contracts/PrivShareAudit.sol` holds (1) each side's approval of each query type - the university
and partner accounts can only change their own side - and (2) an append-only log of query
fingerprints. `logQuery` only accepts calls from the PrivShare backend account, only for types
approved by **both** sides, and only with `groupSize >= 10`; the backend sends `min(n, 10)` so
exact counts stay off-chain. Only SHA-256 fingerprints are stored, never personal data. If the
node is down, queries, approvals and verification are refused (fail closed). Accounts are Anvil's
dev accounts (0 = backend, 1 = university, 2 = partner); in production each organisation would
sign with its own wallet on its own node.

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
| GET | `/api/audit/records?page&per_page` | auditor | off-chain audit log (aggregates and parameters only) |
| GET | `/api/audit/chain` | auditor | contract address, block, number of on-chain records |
| POST | `/api/audit/verify` | auditor | recompute every record's SHA-256 and compare with the chain |
| GET | `/api/admin/alerts?status=open` | admin | anomaly alerts with score, reason, features, which check fired |
| PATCH | `/api/admin/alerts/<id>` | admin | `{status: "reviewed" \| "dismissed"}` |
| POST | `/api/admin/alerts/scan` | admin | re-check every active analyst now |
| GET | `/api/admin/security-events?action&page&per_page` | admin | security log (logins, refusals, approvals, admin actions) |

Verification statuses: `verified`, `tampered` (the stored record changed after it was logged),
`not_on_chain` (no fingerprint, e.g. a redeployed contract), plus `on_chain_without_record`
(a fingerprint whose off-chain record was deleted). The stored `sha256` column is not trusted;
only the on-chain value counts, so editing a record *and* its hash is still caught.

Query body: `{"query_type": "avg_gpa", "filters": {"major": "Cybersecurity", "grad_year": 2024}, "epsilon": 0.5}`

Refusals, in pipeline order: `403 ... not approved ...`, `403 Outside your permissions`,
`403 Query rejected by privacy policy` (group < 10), `403 Privacy budget exhausted`,
`503 Audit service unavailable` (fail closed). If an analyst is limited to some majors (or years),
every query must filter on one of them - a query over "all" would include groups they may not use.

## Sessions

Login sessions are stored server-side (`sessions` table). The cookie carries only a random
token, and the table stores its SHA-256. Logout, deactivation and the 15-minute idle timeout
delete the row, so a copied or replayed cookie stops working.

## Anomaly detection

After every query the analyst's last 30 minutes are scored by an Isolation Forest trained on
normal behaviour, plus a check for counts far beyond anything normal. Suspicious sessions open an
alert for the admin with a plain-language reason. See it work without touching your data:

```powershell
python scripts\simulate_attack.py                       # differencing attack (default)
python scripts\simulate_attack.py --attack averaging    # or: probing
```

Method, features and measured results: [docs/anomaly_detection.md](docs/anomaly_detection.md).

## Differential privacy

The model (what is protected, how noise is calibrated, measured accuracy, and why the mean
uses a bounded model) is in [docs/dp_model.md](docs/dp_model.md).

## Layout

```
backend/        app.py config.py db.py crypto.py auth.py users.py roles.py rbac.py security.py
                events.py sessions.py settings.py catalog.py data_gen.py seed_users.py
                student_store.py ingest.py import_templates.py sis_client.py permissions.py
                dp.py budget.py analytics.py audit.py chain.py contract_deploy.py anomaly.py routes/ tests/
contracts/      PrivShareAudit.sol (the smart contract), deploy.py
university_sim/ simulated university information system (separate Flask service)
samples/        sample_students.csv / .xlsx import templates
scripts/        gen_secrets.py make_cert.py make_samples.py smoke_login.py get_anvil.py run_chain.py
                simulate_attack.py
docs/           dp_model.md anomaly_detection.md
(local only)    tools/ (Anvil), chain/ (saved chain state), contracts/deployment.json
```
