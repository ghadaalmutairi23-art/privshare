# PrivShare – Project Instructions for Claude Code

**PrivShare: A Privacy-Preserving Platform for Sharing University Data with Labor-Market Entities**
Graduation project (Cyber Security Program, Qassim University). A university (data owner) shares student
*statistics* with a labor-market entity such as MHRSD (data consumer). The partner NEVER sees individual records.

Source documents in this folder (read them for details, but this file wins if they disagree):
- `PrivShare_RSD.docx` – requirements (functional, non-functional, technical)
- `technical_implementation_guide.docx` – prototype code for most modules (older version: it says
  "Ministry of Education" and "Ganache"; the current project uses MHRSD/partner and Anvil/Hardhat)
- `PrivShare_Chapters_1_3.docx` – report chapters 1–3 (objectives, scope, requirements FR-01..FR-20, use case, flowchart, architecture)

---

## Architecture (fixed decisions – do not change without asking)

| Layer | Choice |
|---|---|
| Backend | Python 3.11+, **Flask as a JSON REST API only** (no Jinja pages) |
| Frontend | **React + Vite**, separate app in `frontend/`. Use the Vite dev proxy (`/api` → Flask) so cookies stay same-origin |
| Database | SQLite (schema written so it can move to PostgreSQL later), parameterized queries only |
| Passwords / MFA | argon2-cffi, pyotp (TOTP, valid_window=1) |
| Encryption at rest | `cryptography` AESGCM, 256-bit key from env var `DATA_KEY`, 12-byte random nonce per value |
| Differential Privacy | **OpenDP** (Laplace). Fallback allowed: IBM diffprivlib. Keep it behind one module (`dp.py`) |
| Blockchain | Solidity contract on a **local Anvil (Foundry) or Hardhat node**, accessed with web3.py |
| Anomaly detection | scikit-learn IsolationForest on query-log features, pandas/numpy |
| Synthetic data | Faker – at least 500 students |
| Tests | pytest |
| Web hardening | Flask-Limiter (rate limit), CSRF protection, Secure/HttpOnly/SameSite cookies, 15-min idle timeout, HTTPS (self-signed cert for local) |

## Roles (5) – least privilege
- `uni_owner` – University Data Owner: imports/syncs student data, views the university's student records (ONLY this role),
  defines per-analyst permissions, approves query types (university side)
- `partner_rep` – Partner Representative (MHRSD/employer): co-approves query types
- `analyst` – Partner Analyst: runs approved queries within privacy budget, sees aggregates only
- `admin` – System Administrator: manages users/roles; NO access to raw data, cannot edit audit
- `auditor` – Auditor: reads on-chain/off-chain audit log and runs integrity verification

## Data model (minimum)
`students(id, name_enc, national_id_enc, gpa_enc, major, grad_year, coop_completed)` – name, national ID, GPA encrypted.
`users(id, username, pw_hash, totp_secret_enc, role, active)`, `privacy_budget(user_id, epsilon_total, epsilon_spent)`,
`query_types(id, name, approved_uni, approved_partner)`, `audit_records(id, user_id, query_type, params_json, epsilon, group_size, result_noisy, timestamp, sha256, tx_hash)`,
`alerts(id, user_id, score, reason, timestamp)`,
`analyst_permissions(analyst_id, allowed_query_types, allowed_majors, allowed_years, max_queries, queries_used)` – empty list / NULL = "all",
`data_imports(id, source ['csv','excel','api'], filename, rows_ok, rows_rejected, imported_by, timestamp)`.

## University data source + owner features (NEW)
- **Simulated university information system (SIS):** a small separate Flask service (`university_sim/`, own port) that generates
  Faker students and exposes `GET /api/students?page=` with an API key. PrivShare's `uni_owner` clicks "Sync" → backend pulls,
  validates, encrypts sensitive fields, upserts by student number. This simulates connecting to the real university system.
- **Import from Excel/CSV:** `uni_owner` uploads `.csv` or `.xlsx` (pandas + openpyxl). Validate columns
  (student_no, name, national_id, major, gpa 0–5, grad_year, coop_completed), reject bad rows with a report, encrypt, save.
  Provide `sample_students.csv` / `.xlsx` templates. Max file size limit; never keep the uploaded file after import.
- **Owner record view:** paginated/searchable table of students, decrypted in memory ONLY for `uni_owner`; every view is logged.
  Partner roles can never call this endpoint (RBAC + test that proves it returns 403).
- **Analyst permissions (set by uni_owner per analyst):** which query types, which majors (or all), which graduation years (or all),
  max number of queries; the owner can also set the analyst's ε budget. Analysts NEVER see records – permissions only limit what
  they may *calculate on*. Show the analyst their own permissions on the dashboard.

## Allowed queries (whitelist only – never free-form SQL)
1. Number of graduates, 2. Average GPA, 3. Cooperative-training completion rate — each filtered by `major` and `grad_year`.

## Query pipeline (every query, in this order)
1. Authenticated session with MFA done + role `analyst`
2. Query type is in whitelist, ε is within allowed range
3. Smart contract says the query type is approved by **both** university and partner
3b. Query is within the analyst's permissions (query type, major, year, max queries) – otherwise reject "Outside your permissions"
4. Group size ≥ **k = 10** (checked in backend AND in contract) – otherwise unified message "Query rejected by privacy policy"
5. Enough remaining privacy budget – otherwise reject
6. Decrypt needed fields in memory only → compute → add Laplace noise (OpenDP)
7. Deduct ε from budget, save off-chain audit record, write its SHA-256 fingerprint on-chain
8. Return ONLY the noisy aggregate
- **Fail closed:** if the blockchain node is unreachable, refuse the query (never run unlogged).

## Smart contract (keep it small)
`approveQueryType(id)` (records which side approved; executable only when both approved),
`logQuery(bytes32 hash, uint groupSize)` (require approved + groupSize >= 10), `getRecord(i)` / count for verification.
No personal data on-chain — only hashes.

## Anomaly detection
Features per user/time window: queries per window, avg group size, number of distinct filters, ε spent rate, repeated near-identical queries.
Train IsolationForest on synthetic normal logs; include a script that simulates a differencing attack and shows it gets flagged → alert for admin.

## Targets to verify (from objectives / NFRs)
- Average-GPA error within ±0.2 at ε = 0.5 for groups ≥ 100
- Aggregate query ≤ 3 s for 500 records (excluding chain confirm); chain logging ≤ 5 s; pages ≤ 2 s
- 100% of sensitive fields encrypted; 100% of executed queries fingerprinted on-chain; tampered off-chain record detected
- Data persists across restarts

## Suggested repository layout
```
backend/   app.py, config.py, db.py, auth.py, rbac.py, crypto.py, data_gen.py, dp.py, analytics.py,
           chain.py, anomaly.py, audit.py, routes/, tests/
contracts/ PrivShareAudit.sol, deploy script
frontend/  React + Vite app (pages per role)
docs/      notes, screenshots for Chapter 4
.env.example   (DATA_KEY, SECRET_KEY, RPC_URL, CONTRACT_ADDRESS ...)  – real .env is git-ignored
```

## Rules for working on this repo
- Secrets only in environment variables; never hard-code keys; never commit `.env`, keys, or `*.pem`.
- Never return, log, or print individual student records to anyone except the `uni_owner` record-view endpoint (never in logs or test output).
- Work **one phase at a time**. At the end of each phase: run the tests, show how to run it, summarize what was built, and stop for review.
- Write short comments and docstrings; one module per responsibility; add pytest tests for each module.
- If something in the RSD is impossible or unclear, ask instead of silently changing the design.

## Phases (matches the 12-week Gantt)
1. Scaffold + DB + crypto + synthetic data + auth (Argon2 + TOTP) + RBAC + session/CSRF/rate limit
1b. University data: simulated SIS API + sync, CSV/Excel import, owner record view, analyst permissions
2. DP engine (OpenDP) + privacy budget + k-check + query pipeline (with a stub chain client)
2.5. UI design (runs in parallel with Phase 3): clickable mockups of every screen for all 5 roles
   (login + MFA; owner: import/sync + student records + analyst permissions + approvals; analyst: queries + results +
   budget + own permissions; audit + verification; users + alerts), built against the real API.
   Output feeds the report's design chapter and is the spec for Phase 5.
3. Solidity contract + local Anvil/Hardhat deploy + web3.py client + audit verification + fail-closed
4. Isolation Forest anomaly detection + alerts + attack simulation script
5. Implement the React dashboard from the approved Phase 2.5 design (all 5 roles: login + MFA, owner: import/sync + student records + analyst permissions; analyst: queries + charts + remaining budget + own permissions; approvals, audit, alerts, users)
6. Testing & evaluation: full pytest run, accuracy/performance measurements, HTTPS, notes for Wireshark + OWASP ZAP
