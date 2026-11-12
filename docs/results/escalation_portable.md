# Repetition escalation: recovering what the local veto hides

Generated on 2026-11-11. LGBM, 79 features (without port and TCP-window features), k = 50, 30 triaged local flows, seeds 42, 1, 2, 3, 4. Each attack class is left out of all training in turn. A vetoed anomaly alert returns to the queue when at least N vetoed alerts share its destination address and port within 60 s; N is 1 + the most repetition on the earlier evening (3,307 flows), floor 3: N ranged 7–7 over the fitted models. Rule in docs/PREREGISTRATION_ESCALATION.md.

| Unseen class | Anomaly-only detections | Vetoed by the envelope | Returned by escalation | Still lost |
|---|---|---|---|---|
| DoS-Slowloris | 1,109 | 908 | 819 | 89 |
| Infiltration | 35 | 30 | 0 | 30 |
| Web-XSS | 1 | 1 | 0 | 1 |
| **All classes** | **3,200** | **939** | **819** | **120** |

Per seed, share still lost: seed 1 3.8%; seed 2 4.0%; seed 3 3.1%; seed 4 3.7%; seed 42 4.1%.

**H1 (recovery):** lost 29.3% before escalation, 3.8% after (rule: at most 10%): **confirmed**.

| Evening | Alert rate, envelope | With escalation | Rise | Escalated alerts per hour |
|---|---|---|---|---|
| study_wifi_20261101 | 1.75% | 1.75% | +0.00 points | 0.0 |
| study_wifi_20261108 | 1.87% | 1.87% | +0.00 points | 0.0 |

**H2 (price):** rise at most 0.2 points on each evening: **confirmed**.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 114.8 min.
