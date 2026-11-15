# PrivShare – Project Progress

_Last updated: 15 November 2026_

This page shows where the PrivShare implementation stands: what is finished, what is left, and the decisions we made along the way.
For the full design rules see [CLAUDE.md](CLAUDE.md); for setup and the API see [README.md](README.md).

---

## 1. Summary

| Phase | What | Status |
|---|---|---|
| 1 | Backend core: database, encryption, synthetic data, login with MFA, roles, web hardening | ✅ Done |
| 1b | University data: simulated university system + sync, Excel/CSV import, owner record view, analyst permissions | ✅ Done |
| 2 | Differential Privacy engine (OpenDP), privacy budget, k ≥ 10 check, full query pipeline (with a stub blockchain) | ✅ Done |
| 2.5 | UI design: clickable mockups of all screens for the 5 roles | ✅ Done (awaiting team review) |
| 3 | Solidity smart contract on a local blockchain, web3.py client, audit verification | ⏳ Next |
| 4 | AI anomaly detection (Isolation Forest), alerts, attack simulation | ⬜ Not started |
| 5 | React dashboard built from the Phase 2.5 design | ⬜ Not started |
| 6 | Testing & evaluation for the report (accuracy, performance, Wireshark, OWASP ZAP) | ⬜ Not started |

**Automated tests: 190 passing** (`pytest`). Everything runs locally over HTTPS with a self-signed certificate.

---

## 2. What is done

### Phase 1 – Secure core
- **Backend:** Python + Flask, JSON REST API only (the React app will call it).
- **Database:** SQLite, parameterized queries only (no SQL injection). The schema is written so it can move to PostgreSQL later.
- **Encryption at rest:** AES-256-GCM for sensitive student fields (student number, name, national ID, GPA). Each value gets a fresh random nonce, and each ciphertext is bound to its column, so a value copied into another column fails to decrypt. The key comes from the `DATA_KEY` environment variable and is never in the code.
- **Login:** password hashed with **Argon2id**, then a **TOTP 6-digit code** (Google/Microsoft Authenticator).
  - Every failure gives the same message, so an attacker can't tell which part was wrong.
  - Unknown usernames take as long to check as real ones (no username guessing through timing).
  - After 5 wrong codes the user must start again.
  - TOTP secrets are stored encrypted.
- **Sessions are stored on the server.** The cookie holds only a random token; the database stores its SHA-256.
  - Logout, account deactivation and the **15-minute idle timeout** really end the session: a copied cookie stops working.
  - A new token is issued after login (no session fixation).
- **Roles (RBAC), least privilege:** `uni_owner`, `partner_rep`, `analyst`, `admin`, `auditor`. Role and active status are re-checked from the database on every request, so changes apply immediately.
- **Web hardening:**
  - CSRF tokens on every POST/PUT/PATCH
  - rate limits: login 5/min, queries 30/min, uploads 10/min
  - Secure/HttpOnly/SameSite=Strict cookies
  - security headers (HSTS, CSP, no-store, nosniff, frame-deny)
  - request-size limits
- **Security event log:** logins, MFA failures, admin actions, access denials, approvals, data imports and record views. Passwords, codes and personal data are never logged.
- **Admin:** create users (the TOTP setup key is shown once), change roles, deactivate (logs the user out everywhere). The admin has **no access to student data**.

### Phase 1b – University data and owner features
- **Simulated university information system** (`university_sim/`): a separate Flask service on port 5001.
  - It generates synthetic students and serves them page by page behind an **API key**.
  - The owner presses **Sync**: PrivShare pulls all pages over HTTPS, validates each record, encrypts it, and **adds or updates by student number** (no duplicates).
  - The simulator includes 2 deliberately broken records so the rejection report can be demonstrated.
- **Excel/CSV import** (`.csv` or `.xlsx`, max 5 MB):
  - Bad rows are skipped and listed with row number, column and problem. The report never repeats names or IDs.
  - GPAs are checked against the platform's GPA scale (4 or 5).
  - Files are parsed in memory and **never written to disk**.
  - Excel files are checked against "zip bomb" tricks first, and XML parsing uses `defusedxml`.
  - Templates are in [samples/](samples/).
- **Owner record view:** the **only** place individual records leave the server, and only for `uni_owner`.
  - Paginated and searchable, with national IDs **masked** unless revealed one at a time.
  - Every page view and every reveal is logged, without the data itself.
  - Tests prove partner, analyst, admin and auditor all get **403**.
- **Analyst permissions** (set by the owner per analyst): allowed statistics, majors, graduation years, a maximum number of queries, and the analyst's **ε budget**. Analysts can see their own permissions.

### Phase 2 – Differential Privacy and the query pipeline
- **Whitelisted statistics only** (never free-form SQL): number of graduates, average GPA, co-op completion rate, filtered by major and graduation year.
- **Differential Privacy with OpenDP** (Laplace mechanism), all in one module (`backend/dp.py`).
  - OpenDP's own check confirms each answer uses no more than the requested ε before anything is released.
- **Every query goes through this pipeline, in order:**
  1. logged in with MFA, role analyst
  2. allowed statistic, valid filters, ε within range (0.1–1.0)
  3. approved by **both** the university and the partner (checked on the blockchain)
  3b. inside the analyst's permissions → otherwise "Outside your permissions"
  4. group size **≥ 10** → otherwise the single message "Query rejected by privacy policy"
  5. enough privacy budget left
  6. decrypt in memory only → compute → add noise
  7. one transaction: charge ε, count the query, save the audit record, write its **SHA-256 fingerprint on-chain**
  8. return **only** the noisy number
- **Fail closed:** if the blockchain is down, the query is refused and nothing is charged or logged half-way.
- **Privacy budget** is stored in the database and survives restarts. Spent ε is never reset.
- Only `min(group size, 10)` goes on-chain, so the public chain never learns exact counts. The exact size stays in the off-chain audit record for the auditor.
- **Dual-party approval:** the owner and the partner each approve or revoke their own side.
- **Measured results** (details in [docs/dp_model.md](docs/dp_model.md)):
  - Average GPA at ε = 0.5 for 100 students: average error **0.077** (4-point scale), within ±0.2 in **≈ 92 %** of runs.
  - Query time: **33–64 ms** for 500 records (target ≤ 3 s).
- The blockchain is currently a **stub** (an in-memory stand-in that follows the same rules). Phase 3 replaces it with the real contract.

### Phase 2.5 – UI design
- Clickable mockup of **10 screens**:
  - sign in and MFA
  - analyst query page (with permissions and budget)
  - approvals (owner and partner views)
  - auditor log and verification
  - admin users and alerts
  - owner: student data (sync/import), student records, analyst permissions
- It is the spec for the React app in Phase 5, and the screenshots can go in the report's design chapter.
- Link: ask the repo owner to share the design page with you (it is private by default).

---

## 3. What is left

### Phase 3 – Blockchain (next)
- [ ] Install a local node: **Hardhat** (Node.js, easiest on Windows) or **Anvil** (Foundry).
- [ ] Write the Solidity contract `contracts/PrivShareAudit.sol`:
  - `approveQueryType` / `revokeQueryType` (each party controls only its own side)
  - `logQuery(hash, groupSize)`, which requires both approvals and groupSize ≥ 10
  - `getRecord(i)` and `count()` for verification
  - only hashes on-chain, never personal data
- [ ] Deploy script (compile with py-solc-x, write the address and ABI).
- [ ] `web3.py` client replacing the stub (`CHAIN_BACKEND=web3`), with the same interface so the pipeline doesn't change.
- [ ] **Auditor endpoints:** list audit records, and "verify all", which recomputes each record's SHA-256 and compares it with the chain. A tampered record must be detected.
- [ ] Test fail-closed against a real stopped node.
- [ ] Measure: chain logging ≤ 5 s.

### Phase 4 – AI anomaly detection
- [ ] Features per analyst per time window:
  - queries per window
  - average group size
  - number of distinct filters
  - ε spending rate
  - near-identical repeated queries
  - refused queries (already logged in `security_events`)
- [ ] Train **Isolation Forest** (scikit-learn) on synthetic normal behaviour.
- [ ] Attack simulation script: a **differencing attack** (many narrow queries that differ by one filter) that gets flagged.
- [ ] Alerts table + admin endpoints: list alerts, mark reviewed. Also an endpoint for the security event list, which the design shows.

### Phase 5 – React dashboard
- [ ] React + Vite app in `frontend/`, using the Vite proxy so cookies stay on the same origin.
- [ ] Build every screen from the Phase 2.5 design, for all 5 roles.
- [ ] Small API additions the design needs: the analyst's "recent queries" history and the admin security-events list.
- [ ] Charts for results, budget bar, clear refusal messages.
- [ ] Pages must load in ≤ 2 s.

### Phase 6 – Testing & evaluation (for the report)
- [ ] Full pytest run + coverage numbers.
- [ ] Accuracy and performance tables (DP error vs ε and group size, query and chain timings).
- [ ] **Wireshark** capture showing the traffic is encrypted (TLS).
- [ ] **OWASP ZAP** scan of the running app, with the findings and fixes written up.
- [ ] Screenshots and notes in `docs/` for Chapter 4.

---

## 4. Decisions we made (and why)

| Decision | Why |
|---|---|
| Two-step login (password, then code) | Clear UX for the React app; same security as one step. |
| Server-side sessions | A copied or replayed cookie can't survive logout, deactivation or the timeout. |
| GPA scale is a setting (4 or 5), saved with the data | Qassim uses 5 points; the noise bounds must always match the data. |
| Average GPA protects "one student's value" with group size treated as public | The stricter option has ~2.7× more error and would fail the ±0.2 objective. Counts still protect a student's presence. Explained in `docs/dp_model.md`. |
| Only `min(n, 10)` on-chain | The chain only needs to know n ≥ 10; exact counts stay private. |
| The ε budget is set by the **university owner**, not the admin | The data owner controls privacy loss; the admin has no data-related powers. |
| Imported GPAs are checked against the stored scale | Keeps data and noise bounds consistent. |
| A major/year restriction makes that filter required | A query over "all" would include groups the analyst may not use. |
| Only executed queries count toward an analyst's maximum | Refused queries don't use up their quota. |
| National IDs masked in the owner view, revealed one at a time (logged) | The owner sees only what they need. |
| Upload limit 5 MB | Enough for a university-sized file; protects the server. |

---

## 5. Open questions for the team

1. **Default permissions for new analysts.** Right now a new analyst starts with **no restrictions** ("all"), as the data model says. Safer: **nothing allowed until the owner grants it**. That needs a change to CLAUDE.md. Which do we want?
2. **Accuracy objective wording.** Laplace noise is random, so "within ±0.2" can't be guaranteed for every single answer. Suggested wording: _"average absolute error ≤ 0.1 and ≥ 85 % of answers within ±0.2 at ε = 0.5 for groups ≥ 100"_.
3. **Hardhat or Anvil** for Phase 3?

---

## 6. Known limitations (to mention in the report)

- The blockchain is still a stub until Phase 3.
- The k ≥ 10 refusal reveals one bit (the group is small), even with the unified message.
- Budgets are per analyst; several analysts from the same partner could combine theirs. A per-organisation budget would be future work.
- One server decrypts data for computation. Stronger options (TEE, MPC) are out of scope.
- Self-signed certificate: fine for local testing only.

---

## 7. How to run it

See [README.md](README.md). Short version (Windows PowerShell):

```powershell
python -m venv venv; .\venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
python scripts\gen_secrets.py --write      # creates your own .env (never commit it)
python scripts\make_cert.py
python -m backend.seed_users               # prints demo logins + TOTP keys once
python -m university_sim.app               # terminal 1 (port 5001)
python -m backend.app                      # terminal 2 (https://127.0.0.1:5000)
pytest                                     # run all tests
```

**Never commit** `.env`, `certs/`, or the database. They are git-ignored, and each team member generates their own.
