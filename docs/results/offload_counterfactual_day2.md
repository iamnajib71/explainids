# Offload counterfactual: same traffic, wire-sized packets

Generated on 2026-11-02. Frozen detector LGBM trained on cicids2017. Each capture is rewritten with segmentation offload undone (pieces 12 µs apart) and re-extracted; both versions are scored by the same model. Alerts are on unlabelled traffic from networks in ordinary use, so they are candidate false alerts.

| Session | Packets split | Flows (orig → reseg) | Alerts orig | Alerts reseg | Anomaly-only orig → reseg | Paired flows | Alert → clear | Clear → alert |
|---|---:|---|---:|---:|---|---:|---:|---:|
| 25b9887e1868 | 1,994 | 696 → 655 | 65 (9.3%) | 92 (14.0%) | 23 → 51 | 632 | 0 | 23 |
| 260b6df1a3af | 2,414 | 343 → 320 | 21 (6.1%) | 36 (11.2%) | 7 → 27 | 301 | 0 | 11 |
| 5381496e152a | 1,468 | 348 → 330 | 17 (4.9%) | 25 (7.6%) | 6 → 16 | 316 | 0 | 8 |
| e960a2dc6bcf | 1,053 | 294 → 281 | 11 (3.7%) | 17 (6.0%) | 5 → 15 | 261 | 0 | 6 |
| d3f6f0e435b2 | 189 | 290 → 270 | 6 (2.1%) | 9 (3.3%) | 3 → 7 | 259 | 1 | 2 |
| a4a012a6a2a1 | 767 | 208 → 196 | 11 (5.3%) | 16 (8.2%) | 2 → 8 | 190 | 0 | 6 |
| 8d67aa17233b | 337 | 328 → 303 | 17 (5.2%) | 23 (7.6%) | 5 → 13 | 291 | 0 | 6 |
| 8e88b2fb9bcc | 921 | 267 → 252 | 16 (6.0%) | 21 (8.3%) | 6 → 11 | 252 | 0 | 5 |
| 19b37549df88 | 810 | 503 → 477 | 22 (4.4%) | 32 (6.7%) | 13 → 24 | 461 | 2 | 13 |
| ec9c40fca2de | 931 | 423 → 396 | 21 (5.0%) | 23 (5.8%) | 6 → 13 | 391 | 0 | 6 |
| bc58043917e4 | 629 | 493 → 472 | 21 (4.3%) | 29 (6.1%) | 12 → 24 | 465 | 0 | 9 |
| 6918d459caab | 1,391 | 441 → 422 | 8 (1.8%) | 11 (2.6%) | 1 → 6 | 417 | 0 | 4 |

## Pooled

| Measure | Value |
|---|---|
| Alerts, original capture | 236 / 4634 (5.1%, 95% CI 4.5%–5.8%) |
| Alerts, offload undone | 334 / 4374 (7.6%, 95% CI 6.9%–8.5%) |
| Paired alerts that clear when offload is undone | 3 of 211 |
| … of which on flows that contained super-packets | 2 |
| Paired flows that newly alert | 99 of 4236 |
| Exact McNemar test (alert→clear vs clear→alert) | p = 7e-26 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 0.9 min.
