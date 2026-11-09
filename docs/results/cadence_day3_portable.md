# Refit cadence: 9 days old (30 Oct) versus 1 day old (7 Nov) (H3)

Generated on 2026-11-09. 79 features (without port and TCP-window features); seeds 42, 1, 2, 3, 4. Every condition is scored on 8 November. Both pools subsampled to the smaller size, three draws each. Rule in docs/PREREGISTRATION_DAY3.md.

| Local traffic used for the repair | Flows | Alerts, 8 November (mean of seeds) | Benchmark detection |
|---|---|---|---|
| few-shot (no repair) | 0 | 5.2% | 0.962 |
| 9 days old (30 Oct), full | 3,307 | 2.2% | 0.960 |
| 1 day old (7 Nov), full | 4,629 | 0.9% | 0.956 |
| 9 days old (30 Oct), 3307-flow draw 1 | 3,307 | 2.1% | 0.956 |
| 1 day old (7 Nov), 3307-flow draw 1 | 3,307 | 1.0% | 0.960 |
| 9 days old (30 Oct), 3307-flow draw 2 | 3,307 | 2.2% | 0.958 |
| 1 day old (7 Nov), 3307-flow draw 2 | 3,307 | 1.2% | 0.960 |
| 9 days old (30 Oct), 3307-flow draw 3 | 3,307 | 1.9% | 0.960 |
| 1 day old (7 Nov), 3307-flow draw 3 | 3,307 | 1.0% | 0.958 |

**Primary (H3):** 9 days old (30 Oct) 1.57% vs 1 day old (7 Nov) 0.81% at equal size (block means); difference +0.76% (95% block bootstrap +0.40% to +1.15%); old higher in 12, lower in 0, ties 0, sign test p = 0.000: **decay detected**.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 63.4 min.
