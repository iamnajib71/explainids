# Attack Night: minutes of attacker freedom

Generated on 2026-11-08. 83 features (all features); seeds 42, 1, 2, 3, 4; one hour of real household traffic (4,634 flows, untouched second evening) with a lab attack campaign (run_20261025T050628Z: 264 flows, run_20261025T051149Z: 264 flows) inserted at 20 random moments per seed and replicate. FIFO analyst. Rules in docs/PREREGISTRATION_ATTACK_NIGHT.md.

| Analyst pace | Detector | Household alerts / hour | Time to notice, median (IQR) | Attack missed | Over before noticed |
|---|---|---|---|---|---|
| 1 per 30 s | Deployed | 288 | 46.3 min (39.3 min–60.0 min) | 0% | 100% |
| 1 per 30 s | Repaired | 46 | 7 s (7 s–26 s) | 0% | 19% |
| 1 per 30 s | Poisoned | 47 | 7 s (7 s–30 s) | 0% | 21% |
| 1 per 30 s | Poisoned, gated | 47 | 7 s (7 s–36 s) | 0% | 22% |
| 1 per 60 s | Deployed | 288 | 125.9 min (101.3 min–165.1 min) | 0% | 100% |
| 1 per 60 s | Repaired | 46 | 5.5 min (23 s–12.5 min) | 0% | 68% |
| 1 per 60 s | Poisoned | 47 | 5.9 min (24 s–12.4 min) | 0% | 70% |
| 1 per 60 s | Poisoned, gated | 47 | 6.0 min (43 s–13.1 min) | 0% | 72% |
| 1 per 120 s | Deployed | 288 | 278.2 min (223.0 min–369.7 min) | 0% | 100% |
| 1 per 120 s | Repaired | 46 | 39.9 min (38.1 min–43.1 min) | 0% | 100% |
| 1 per 120 s | Poisoned | 47 | 41.0 min (38.1 min–44.8 min) | 0% | 100% |
| 1 per 120 s | Poisoned, gated | 47 | 40.5 min (37.4 min–45.1 min) | 0% | 100% |
| 1 per 300 s | Deployed | 288 | 731.7 min (585.7 min–992.2 min) | 0% | 100% |
| 1 per 300 s | Repaired | 46 | 148.2 min (135.6 min–164.5 min) | 0% | 100% |
| 1 per 300 s | Poisoned | 47 | 151.1 min (138.1 min–166.0 min) | 0% | 100% |
| 1 per 300 s | Poisoned, gated | 47 | 152.8 min (136.6 min–167.3 min) | 0% | 100% |

**H1 (1 alert per 60 s):** Deployed 125.9 min vs Repaired 5.5 min; Wilcoxon p = 1.4e-34 over 200 paired injections: **confirmed**.
Per-seed medians (min): Deployed [137.4442856381257, 110.84923286121209, 106.66686162132156, 122.43605552692352, 111.52416781566653], Repaired [6.136262470285489, 3.752475170681572, 6.393943471393749, 4.76447686474584, 3.176383576552853].

**H2:** missed, Deployed 0% vs Repaired 0%.

**H3:** port-scan and SYN-burst flows flagged: Repaired 100%, Poisoned 23%, Poisoned + gate 100%; missed 0% / 0% / 0%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 16.1 min.
