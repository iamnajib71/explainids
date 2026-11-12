# Repair loop, end to end through the API

Generated on 2026-11-03 by `scripts/repair_loop_check.py`. Shipped model: CIC-IDS2017 only. Every step uses the console's own API in-process; the household's traffic is assumed benign, as in the study.

| Step | Measure | Result |
|---|---|---|
| Shipped model, second evening | alerts / flows | 236 / 4,634 (5.1%) |
| Shipped model | lab attacks caught (other replicates) | 90.9% of 528 |
| Triage, first evening | household alerts dismissed | 190 |
| Triage | lab attacks dismissed by mistake | 3; at decision time: unchecked (no site envelope), unchecked (no site envelope), unchecked (no site envelope) |
| Repair (`repair_model.py`) | dismissals used / held back by the gate | 190 / 3 |
| Repair | wrongly dismissed attacks that passed the gate | 0 of 3 |
| Repair | local normal flows in the site envelope | 3,307 |
| Repair | benchmark macro F1 / attack recall / benign FPR, before → after | 0.862 → 0.880 / 0.9976 → 0.9976 / 0.55% → 0.54% |
| Repaired model, second evening | alerts / flows | 45 / 4,634 (1.0%) |
| Repaired model | low-priority (vetoed, kept) | 93 |
| Repaired model | lab attacks caught (other replicates) | 90.9% |
| Repaired model | wrong dismissals of caught attacks | held back, held back, held back |

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 1.5 min.
