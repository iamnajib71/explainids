# Attack Night: minutes of attacker freedom

Generated on 2026-11-08. 79 features (without port and TCP-window features); seeds 42, 1, 2, 3, 4; one hour of real household traffic (4,634 flows, untouched second evening) with a lab attack campaign (run_20261025T050628Z: 264 flows, run_20261025T051149Z: 264 flows) inserted at 20 random moments per seed and replicate. FIFO analyst. Rules in docs/PREREGISTRATION_ATTACK_NIGHT.md.

| Analyst pace | Detector | Household alerts / hour | Time to notice, median (IQR) | Attack missed | Over before noticed |
|---|---|---|---|---|---|
| 1 per 30 s | Deployed | 308 | 47.4 min (41.4 min–62.2 min) | 0% | 100% |
| 1 per 30 s | Repaired | 94 | 1.6 min (7 s–4.8 min) | 0% | 56% |
| 1 per 30 s | Poisoned | 94 | 1.1 min (7 s–4.3 min) | 0% | 52% |
| 1 per 30 s | Poisoned, gated | 93 | 1.2 min (7 s–5.2 min) | 0% | 53% |
| 1 per 60 s | Deployed | 308 | 125.1 min (101.4 min–168.9 min) | 0% | 100% |
| 1 per 60 s | Repaired | 94 | 13.1 min (8.2 min–23.3 min) | 0% | 98% |
| 1 per 60 s | Poisoned | 94 | 13.0 min (7.5 min–27.8 min) | 0% | 99% |
| 1 per 60 s | Poisoned, gated | 93 | 13.3 min (7.9 min–26.9 min) | 0% | 96% |
| 1 per 120 s | Deployed | 308 | 280.0 min (225.5 min–380.8 min) | 0% | 100% |
| 1 per 120 s | Repaired | 94 | 53.7 min (40.0 min–100.5 min) | 0% | 100% |
| 1 per 120 s | Poisoned | 94 | 49.1 min (44.3 min–106.0 min) | 0% | 100% |
| 1 per 120 s | Poisoned, gated | 93 | 54.5 min (38.5 min–106.9 min) | 0% | 100% |
| 1 per 300 s | Deployed | 308 | 743.8 min (587.7 min–1012.3 min) | 0% | 100% |
| 1 per 300 s | Repaired | 94 | 188.8 min (141.7 min–325.5 min) | 0% | 100% |
| 1 per 300 s | Poisoned | 94 | 179.4 min (143.6 min–319.1 min) | 0% | 100% |
| 1 per 300 s | Poisoned, gated | 93 | 174.3 min (128.2 min–332.0 min) | 0% | 100% |

**H1 (1 alert per 60 s):** Deployed 125.1 min vs Repaired 13.1 min; Wilcoxon p = 1.4e-34 over 200 paired injections: **confirmed**.
Per-seed medians (min): Deployed [110.33888894581979, 125.34923286121209, 102.07759063970518, 138.43605552692352, 137.25904525114683], Repaired [5.260745098928799, 13.165449471610545, 51.800132729555195, 12.1647563550127, 11.747309922766297].

**H2:** missed, Deployed 0% vs Repaired 0%.

**H3:** port-scan and SYN-burst flows flagged: Repaired 100%, Poisoned 59%, Poisoned + gate 100%; missed 0% / 0% / 0%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 17.2 min.
