# Differential Privacy model used by PrivShare

This note states exactly what PrivShare's Differential Privacy (DP) protects, so it can be
quoted in the report (Chapters 3–4). Implementation: `backend/dp.py` (OpenDP 0.16, Laplace mechanism).

## 1. What is public and what is protected

| Data | Status | Reason |
|---|---|---|
| Major, graduation year | Filter attributes (stored in clear) | Used only to select a group. Allowed values are institutional metadata (`/api/query/options`). |
| GPA, co-op completion | **Protected values** | Never leave the server except inside a noisy aggregate. |
| Name, national ID | **Never used in any query** | Stored encrypted (AES-256-GCM). |
| Whether a student is in a group | **Protected** for counts | See 2.1. |
| Exact group size *n* | Never returned to the analyst; kept off-chain | Stored in the off-chain audit record. Only `min(n, k)` is sent to the blockchain, so the chain learns only "n ≥ k". |

## 2. Neighbouring datasets per query type

DP compares two datasets that differ in one student. PrivShare uses the following definition for each query type:

### 2.1 Number of graduates (count)
- **Neighbours:** one student added or removed from the group.
- **Sensitivity:** 1.
- **Mechanism:** discrete Laplace with scale 1/ε. The output is rounded to an integer and floored at 0.
- **Guarantee:** an analyst cannot reliably tell whether any one student is in the group.

### 2.2 Average GPA and co-op completion rate (bounded mean)
- **Neighbours:** one student's *value* (GPA or co-op flag) changed, with the group size n fixed.
- **Bounds:** each value is clamped to [0, GPA scale] for GPA and [0, 1] for co-op.
- **Sensitivity:** (upper − lower) / n.
- **Mechanism:** Laplace with scale (upper − lower) / (n·ε). The output is clipped to the valid range.
- **Guarantee:** an analyst cannot reliably learn any one student's GPA or co-op status.

In both cases OpenDP's privacy map is evaluated before release, and a result is only released if the map confirms the privacy loss is at most ε (`dp.py: _calibrate`). Clamping and rounding the output is post-processing, so it does not weaken the guarantee.

### Why the mean uses the "value changed" definition
The stricter alternative protects add/remove for the mean as well. It computes a noisy sum and a noisy count, splitting ε between them, and divides one by the other. We measured both approaches at ε = 0.5 (`|noisy − true|` of the average GPA, thousands of runs):

| GPA scale | n | **Chosen: mean error** | **Chosen: within ±0.2** | Strict: mean error | Strict: within ±0.2 |
|---|---|---|---|---|---|
| 4 | 100 | **0.077** | **92.7 %** | 0.212 | 58.6 % |
| 4 | 200 | **0.041** | **99.3 %** | 0.107 | 84.9 % |
| 5 | 100 | **0.099** | **87.6 %** | 0.258 | 50.6 % |
| 5 | 200 | **0.049** | **98.4 %** | 0.133 | 77.5 % |

The strict version has about 2.7× the error and would not meet Objective 2 (±0.2 for groups ≥ 100). The presence of a student in a group is still protected by the count query (2.1) and by the k-threshold, and n is never shown to the analyst. We therefore accept the bounded model for means and state it as a design decision.

## 3. Repeated queries and the budget
- Every executed query spends its ε from the analyst's persistent budget (default 5.0).
- Under sequential composition, the total privacy loss of an analyst is at most the sum of the ε values spent, so the budget caps it.
- Spent ε is never reset; an admin can only change the total (`PATCH /api/admin/users/<id>/budget`).
- Groups smaller than k = 10 are refused with one unified message, and no budget is spent.

## 4. Accuracy objective – suggested wording
Laplace noise is random, so no single answer can be guaranteed within ±0.2. We suggest wording Objective 2 as follows:
> "At ε = 0.5 and groups of at least 100 students, the average absolute error of the average-GPA
> query is ≤ 0.1 (measured 0.077 on a 4-point scale and 0.099 on a 5-point scale), and at least 85 % of answers fall within ±0.2."

## 5. Known limits (for the report)
- The k-threshold check itself reveals one bit: whether n ≥ 10. The unified message hides which rule refused the query, but it does not hide that a refusal happened.
- The budget is per analyst. Several analysts from the same partner who collude can combine their budgets. A per-organisation budget would be future work.
- The DP guarantee assumes each student appears once in the data (true for the synthetic data).
