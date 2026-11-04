# Refit cadence: does the site's model of normal age? (C3)

Generated on 2026-11-04. 79 features (without port and TCP-window features); seeds 42, 1, 2, 3, 4. Every condition is scored on the 1 November evening. Rule in docs/PREREGISTRATION_CONFIRM.md.

| Local traffic used for the repair | Flows | Alerts, 1 Nov (mean of seeds) | Benchmark detection |
|---|---|---|---|
| few-shot (no repair) | 0 | 6.6% | 0.962 |
| 3 days old (29 Oct pilot) | 222 | 2.1% | 0.958 |
| 2 days old (30 Oct, full) | 3,307 | 2.0% | 0.960 |
| 2 days old (30 Oct, 222-flow draw 1) | 222 | 2.2% | 0.958 |
| 2 days old (30 Oct, 222-flow draw 2) | 222 | 2.3% | 0.957 |
| 2 days old (30 Oct, 222-flow draw 3) | 222 | 2.3% | 0.962 |

**Primary (C3):** 3-day-old pool 2.03% vs 2-day-old pool of equal size 2.11% (block means); old higher in 4, lower in 8, ties 0, sign test p = 0.388: **no decay detected** at this age difference.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 537.3 min.
