# Anomaly detection in PrivShare

This note explains how PrivShare detects suspicious analyst behaviour, and gives the measured results for the report (Chapters 3–4).
Code: `backend/anomaly.py`. Demo: `python scripts/simulate_attack.py`.

## 1. What we are looking for

Differential privacy and the k ≥ 10 rule protect every single answer. A determined analyst can still try to learn about individuals by combining **many** answers:

| Attack | What the attacker does | Why it is dangerous |
|---|---|---|
| **Differencing** | Asks the same statistic for a group and for each of its sub-groups (e.g. a major, then that major per graduation year), several times | Subtracting answers can isolate a small set of students |
| **Noise averaging** | Repeats one narrow query many times with a tiny ε | Averaging many noisy answers cancels the noise |
| **Small-group probing** | Sweeps many narrow major × year groups looking for tiny ones | Finds groups close to a single person |

The privacy budget limits how far any of these can go. The anomaly detector tells the **administrator** that someone is trying.

## 2. Features (per analyst, last 30 minutes)

| Feature | Meaning |
|---|---|
| `n_queries` | Queries asked, executed or refused |
| `n_refused` | Queries refused by the pipeline (k-rule, permissions, budget …) |
| `avg_group_size` | Mean group size of executed queries (small = narrow probing) |
| `distinct_filters` | Different statistic + filter combinations used |
| `eps_spent` | Privacy budget spent in the window |
| `repeats` | Queries identical to an earlier one in the window |
| `repeat_share` | `repeats / n_queries` |

Executed queries come from the off-chain audit log; refused ones come from the security log. Neither contains student data.

## 3. Method

- **Isolation Forest** (scikit-learn, 200 trees, `contamination = 0.01`).
  - It is trained **unsupervised**, on 3,000 synthetic windows of *normal* analyst behaviour: a few varied, mostly broad queries, occasional repeats and refusals, and sometimes ε = 0.1.
  - It never sees an attack while training.
  - The alert threshold is learnt from that normal data: about 1 % of normal windows fall above it.
- **Far-beyond-normal check (hybrid).** An Isolation Forest cannot rank a value beyond everything it saw in training as "more abnormal". A session with 25 queries lands in the same leaf as the busiest normal session. So a window is also flagged when a count (queries, refusals, distinct filters, repeats) reaches **1.5× the largest value seen in normal training**. Every alert records which check fired (`model`, `far_beyond_normal`, or both).
- **When it runs:** after every query (executed or refused), for that analyst's last 30 minutes. The admin can also trigger a scan of all analysts. At most one open alert exists per analyst per window; it is updated if the behaviour gets worse.
- **Explainable alerts:** the reason lists each feature outside the normal range (above the 99th percentile of normal training), for example *"19 queries in the window (normal ≤ 8); 18 repeated identical queries (normal ≤ 2); 95% of queries were repeats (normal ≤ 50%)"*.
- **Admin workflow:** list alerts, mark them *reviewed* or *dismissed* (who and when is recorded), and deactivate the analyst if needed. The security log shows every step.

## 4. Results

Evaluation on fresh synthetic windows, never used in training:

| Set | Windows | Flagged |
|---|---|---|
| Normal analysts | 5,000 | **0.7 %** (false alarms) |
| Honest analysts who always use ε = 0.1 | 2,000 | 1.2 % |
| Differencing attack | 500 | **100 %** |
| Noise-averaging attack | 500 | **100 %** |
| Small-group probing | 500 | **100 %** |
| Differencing, no refusals (realistic on our data) | 500 | **100 %** |
| Probing, no refusals | 500 | **100 %** (model alone 68.8 %; the far-beyond check covers the rest) |

**End-to-end simulation** (`scripts/simulate_attack.py`): 3 normal analysts and 1 attacker use the real pipeline. Across 3 attack types × 3 random seeds, **9/9 runs alerted the attacker and never a normal analyst**.

**Live test** (HTTPS, real blockchain): an analyst repeating one narrow query was alerted **after the 4th query**. Queries took about 0.19 s each, including the on-chain write and the anomaly check.

## 5. Design decisions and what we tried

- **A seventh feature, `repeat_share`, was added** to the five in the project brief. With only exact-repeat counts, realistic differencing attacks sat right on the threshold (34 % detected). Adding the share raised this to 100 % and *lowered* false alarms (1.0 % → 0.9 %).
- **"Near-identical" queries** (the same statistic, filters differing in one field) were tried as a replacement for exact repeats. They did not help, because honest analysts also compare neighbouring groups.
- **Average ε per query** as a feature was tried and rejected. It doubled false alarms for honest analysts who prefer strong privacy (ε = 0.1), without catching more attacks.
- **The training data includes honest analysts choosing ε = 0.1.** A low ε alone must never look suspicious.

## 6. Limitations (for the report)

- The model is trained on **synthetic** normal behaviour. With a real deployment it should be retrained on the platform's own logs after a learning period.
- A patient attacker who spreads queries over many 30-minute windows looks normal in each window. Longer windows (or a second, daily window) and the privacy budget are the defences there.
- The detector raises alerts; it does not block. Blocking is the admin's decision (deactivate the account), on purpose, to avoid locking out honest users because of false alarms.
