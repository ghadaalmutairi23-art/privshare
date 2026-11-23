# PrivShare – Project Progress

_Last updated: 23 November 2026 (Phase 4)_

This page shows where the PrivShare implementation stands: what is finished, what is left, and the decisions we made along the way.
For the full design rules see [CLAUDE.md](CLAUDE.md); for setup and the API see [README.md](README.md).

---

## 1. Summary

| Phase | What | Status |
|---|---|---|
| 1 | Backend core: database, encryption, synthetic data, login with MFA, roles, web hardening | ✅ Done |
| 1b | University data: simulated university system + sync, Excel/CSV import, owner record view, analyst permissions | ✅ Done |
| 2 | Differential Privacy engine (OpenDP), privacy budget, k ≥ 10 check, full query pipeline | ✅ Done |
| 2.5 | UI design: clickable mockups of all screens for the 5 roles | ✅ Done (awaiting team review) |
| 3 | Solidity smart contract on a local blockchain (Anvil), web3.py client, audit verification | ✅ Done |
| 4 | AI anomaly detection (Isolation Forest), alerts, attack simulation | ✅ Done |
| 5 | React dashboard built from the Phase 2.5 design | ⏳ Next |
| 6 | Testing & evaluation for the report (accuracy, performance, Wireshark, OWASP ZAP) | ⬜ Not started |

**Automated tests: 231 passing** (`pytest`), including tests against the real contract on a real Anvil node. Everything runs locally over HTTPS with a self-signed certificate.

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

### Phase 3 – Blockchain
- **Local node: Anvil** (Foundry), downloaded by `scripts/get_anvil.py` with a pinned version and a verified checksum.
  - `scripts/run_chain.py` saves the chain to disk and reloads it, so it **survives restarts**. Hardhat's node can't do this, which is why we chose Anvil.
- **Smart contract** `contracts/PrivShareAudit.sol` (Solidity 0.8.28):
  - `approveQueryType` / `revokeQueryType`: the university and the partner each control only their own side.
  - `logQuery(queryType, hash, groupSize)`:
    - only the PrivShare backend account may call it
    - the query type must be approved by **both** sides
    - `groupSize` must be **≥ 10**
    - the hash must not be empty
  - `getRecord(i)` and `count()` for verification.
  - **Only SHA-256 fingerprints on-chain**, never personal data.
- **Deploy script** `contracts/deploy.py`: compiles with py-solc-x and writes the address, ABI and account roles to `contracts/deployment.json` (local only). It refuses to replace a live contract unless you pass `--force`.
- **web3.py client** (`CHAIN_BACKEND=web3`, now the default):
  - It has the same interface as the stub, so the pipeline didn't change.
  - Each audit record stores its transaction hash and its position on-chain.
- **Auditor endpoints:** list the audit log, chain info, and **verify all**. Verify recomputes each record's SHA-256 and compares it with the chain. It reports `verified`, `tampered`, `not_on_chain`, and fingerprints whose record was deleted. Rewriting a record *and* its stored hash is still caught, because only the on-chain value is trusted.
- **Approvals are read from the contract.** The database copy is only a fallback, marked as such when the node is down.
- **Fail closed, tested on a real stopped node:** queries, approvals and verification are refused, and nothing is charged or half-written.
- **Measured live:** about **0.07 s per query including the on-chain write** (target ≤ 5 s). The first transaction after start-up takes about 2.8 s while the connection warms up.

### Phase 4 – AI anomaly detection
- **Seven features per analyst** over the last 30 minutes: queries, refused queries, average group size, distinct filter combinations, ε spent, repeated identical queries, and the share of repeats.
- **Isolation Forest** (scikit-learn) trained unsupervised on 3,000 synthetic windows of normal behaviour. It is never shown an attack.
- **Hybrid check:** counts far beyond anything seen in normal use (≥ 1.5× the training maximum) are flagged too. This covers a known Isolation Forest blind spot. Every alert says which check fired.
- **Runs after every query** (executed or refused) for that analyst. A failure in detection never breaks the query.
- **Alerts for the admin:** score, a plain-language reason, the features, and *reviewed / dismissed* tracking. The admin can also scan all analysts at once and read the **security event log**.
- **`scripts/simulate_attack.py`:** three normal analysts and one attacker (differencing, noise-averaging or probing) use the real pipeline, and the script shows who gets flagged.
- **Measured** (details in [docs/anomaly_detection.md](docs/anomaly_detection.md)):
  - **0.7 % false alarms** on 5,000 unseen normal sessions.
  - **100 % detection** of all three attack types, including realistic versions with no refused queries.
  - **9/9 simulations** alerted only the attacker.
  - Live over HTTPS: an attacker was alerted after their **4th** repeated query.

---

## 3. What is left

### Phase 5 – React dashboard (next)
- [ ] React + Vite app in `frontend/`, using the Vite proxy so cookies stay on the same origin.
- [ ] Build every screen from the Phase 2.5 design, for all 5 roles.
- [ ] One small API addition the design needs: the analyst's "recent queries" history. The admin security-events list is already done.
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
| **Anvil** instead of Hardhat | Anvil saves the chain to disk; Hardhat's node forgets everything on restart, which would break "data persists across restarts". |
| `logQuery` also takes the query type, and the contract has `revokeQueryType` | The contract must know which type to check for approval; withdrawing approval was requested by the team. |
| Only the backend account can log queries | Nobody else can add fake fingerprints to the log. |
| Anvil's unlocked dev accounts (0 = backend, 1 = university, 2 = partner) | No private keys stored in PrivShare for the prototype. In production each organisation signs with its own wallet on its own node. |
| Anomaly detection adds a 7th feature, the share of repeated queries | With repeats counted only, realistic differencing attacks sat on the threshold (34 % detected); with the share, 100 %, and fewer false alarms. |
| Hybrid: Isolation Forest + "far beyond normal" check | The model can't score a session as stranger than the most extreme normal one; the check covers that, and each alert says which fired. |
| Alerts warn the admin; they don't block automatically | False alarms must not lock out honest analysts. The admin decides (deactivate the account), and the privacy budget limits damage in the meantime. |

---

## 5. Open questions for the team

1. **Default permissions for new analysts.** Right now a new analyst starts with **no restrictions** ("all"), as the data model says. Safer: **nothing allowed until the owner grants it**. That needs a change to CLAUDE.md. Which do we want?
2. **Accuracy objective wording.** Laplace noise is random, so "within ±0.2" can't be guaranteed for every single answer. Suggested wording: _"average absolute error ≤ 0.1 and ≥ 85 % of answers within ±0.2 at ε = 0.5 for groups ≥ 100"_.

---

## 6. Known limitations (to mention in the report)

- The blockchain is a single local node holding all three accounts. A real deployment would have one node (and one wallet) per organisation, e.g. a permissioned network.
- If the node confirms a fingerprint but the response is lost, the query is rolled back off-chain. The auditor's verify then shows that fingerprint as "on-chain without record", so it is visible, not hidden.
- The k ≥ 10 refusal reveals one bit (the group is small), even with the unified message.
- Budgets are per analyst; several analysts from the same partner could combine theirs. A per-organisation budget would be future work.
- One server decrypts data for computation. Stronger options (TEE, MPC) are out of scope.
- The anomaly model is trained on synthetic normal behaviour. A real deployment should retrain it on its own logs. A patient attacker who spreads queries over many 30-minute windows looks normal per window; the privacy budget is the defence there.
- Self-signed certificate: fine for local testing only.

---

## 7. How to run it

See [README.md](README.md). Short version (VS Code terminal on Windows):

```powershell
python -m venv venv
venv/Scripts/activate
pip install -r backend\requirements.txt
python scripts\gen_secrets.py --write      # creates your own .env (never commit it)
                                           # already have a .env? use --add-missing instead
python scripts\make_cert.py
python scripts\get_anvil.py                # downloads the local blockchain node (once)
python -m backend.seed_users               # prints demo logins + TOTP keys once
python scripts\run_chain.py                # terminal 1: blockchain (keep open)
python contracts\deploy.py                 # once, after the chain is running
python -m university_sim.app               # terminal 2 (port 5001)
python -m backend.app                      # terminal 3 (https://127.0.0.1:5000)
pytest                                     # run all tests
```

**Never commit** `.env`, `certs/`, `tools/`, `chain/`, `contracts/deployment.json` or the database. They are git-ignored, and each team member generates their own.
