# Offload counterfactual: same traffic, wire-sized packets

Generated on 2026-10-31. Frozen detector LGBM trained on cicids2017. Each capture is rewritten with segmentation offload undone (pieces 1 µs apart) and re-extracted; both versions are scored by the same model. Alerts are on unlabelled traffic from networks in ordinary use, so they are candidate false alerts.

| Session | Packets split | Flows (orig → reseg) | Alerts orig | Alerts reseg | Anomaly-only orig → reseg | Paired flows | Alert → clear | Clear → alert |
|---|---:|---|---:|---:|---|---:|---:|---:|
| a31813fe874a | 5,481 | 171 → 166 | 18 (10.5%) | 18 (10.8%) | 12 → 17 | 161 | 2 | 2 |
| 18040510ab5a | 1,236 | 628 → 597 | 73 (11.6%) | 86 (14.4%) | 21 → 36 | 568 | 0 | 12 |
| fd7c18aee195 | 1,310 | 511 → 488 | 23 (4.5%) | 38 (7.8%) | 10 → 33 | 454 | 0 | 12 |
| bb41af7a1a40 | 270 | 193 → 182 | 5 (2.6%) | 6 (3.3%) | 3 → 5 | 175 | 0 | 1 |
| 7445697e96da | 73 | 195 → 190 | 5 (2.6%) | 8 (4.2%) | 4 → 7 | 187 | 0 | 3 |
| 959fd2ad1492 | 84 | 146 → 137 | 5 (3.4%) | 7 (5.1%) | 4 → 6 | 127 | 0 | 1 |
| 275e098c3de1 | 68 | 140 → 135 | 4 (2.9%) | 6 (4.4%) | 2 → 4 | 127 | 0 | 2 |
| 490dada0883f | 69 | 121 → 113 | 4 (3.3%) | 5 (4.4%) | 3 → 4 | 102 | 0 | 0 |
| e1b65b1b6eed | 67 | 150 → 145 | 5 (3.3%) | 6 (4.1%) | 4 → 5 | 144 | 1 | 1 |
| 1f3f824dff1e | 186 | 136 → 127 | 8 (5.9%) | 9 (7.1%) | 6 → 8 | 119 | 1 | 2 |
| 48d155ff5719 | 75 | 136 → 131 | 7 (5.1%) | 9 (6.9%) | 6 → 8 | 123 | 0 | 2 |
| e195702ebf11 | 2,080 | 567 → 521 | 28 (4.9%) | 34 (6.5%) | 21 → 27 | 500 | 2 | 5 |
| cb52327ed7f5 | 2,620 | 384 → 349 | 23 (6.0%) | 33 (9.5%) | 19 → 31 | 339 | 0 | 8 |

## Pooled

| Measure | Value |
|---|---|
| Alerts, original capture | 208 / 3478 (6.0%, 95% CI 5.2%–6.8%) |
| Alerts, offload undone | 265 / 3281 (8.1%, 95% CI 7.2%–9.1%) |
| Paired alerts that clear when offload is undone | 6 of 189 |
| … of which on flows that contained super-packets | 5 |
| Paired flows that newly alert | 51 of 3126 |
| Exact McNemar test (alert→clear vs clear→alert) | p = 5.7e-10 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 2.4 min.
