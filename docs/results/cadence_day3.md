# Refit cadence: 9 days old (30 Oct) versus 1 day old (7 Nov) (H3)

Generated on 2026-11-09. 83 features (all features); seeds 42, 1, 2, 3, 4. Every condition is scored on 8 November. Both pools subsampled to the smaller size, three draws each. Rule in docs/PREREGISTRATION_DAY3.md.

| Local traffic used for the repair | Flows | Alerts, 8 November (mean of seeds) | Benchmark detection |
|---|---|---|---|
| few-shot (no repair) | 0 | 5.1% | 0.980 |
| 9 days old (30 Oct), full | 3,307 | 0.5% | 0.981 |
| 1 day old (7 Nov), full | 4,629 | 0.6% | 0.980 |
| 9 days old (30 Oct), 3307-flow draw 1 | 3,307 | 0.5% | 0.981 |
| 1 day old (7 Nov), 3307-flow draw 1 | 3,307 | 0.6% | 0.979 |
| 9 days old (30 Oct), 3307-flow draw 2 | 3,307 | 0.6% | 0.982 |
| 1 day old (7 Nov), 3307-flow draw 2 | 3,307 | 0.6% | 0.980 |
| 9 days old (30 Oct), 3307-flow draw 3 | 3,307 | 0.4% | 0.982 |
| 1 day old (7 Nov), 3307-flow draw 3 | 3,307 | 0.6% | 0.979 |

**Primary (H3):** 9 days old (30 Oct) 0.43% vs 1 day old (7 Nov) 0.45% at equal size (block means); difference -0.02% (95% block bootstrap -0.14% to +0.13%); old higher in 4, lower in 8, ties 0, sign test p = 0.388: **no decay detected** at this age.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 133.7 min.
