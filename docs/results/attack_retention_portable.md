# Attack retention, poisoning, data budget and evasion of the local repair

Generated on 2026-11-02. Model LGBM, 79 features (without port and TCP-window features), k = 50, 30 triaged local flows, seeds 42, 1, 2, 3, 4. Local model of normal fitted on 3,307 flows from an earlier evening; false alerts measured on 4,634 flows of a later evening. Lab attacks: 792 flows from three isolated-lab replicates (run_20261025T050509Z, run_20261025T050628Z, run_20261025T051149Z); poisoning uses replicate A's 264 attacks and is scored on the other two (528 attacks). Means over seeds; decision rules are in the script docstring.

## R1. Does the repair keep catching attacks?

| Variant | Lab attack recall | Benchmark detection | Caught by anomaly layer alone: lab / benchmark | Lab benign false alerts | Real-network alerts |
|---|---|---|---|---|---|
| few-shot | 86.4% | 0.962 | 0.0% / 0.0% | 0.0% | 6.6% |
| triaged, benchmark anomaly layer | 86.4% | 0.961 | 0.0% / 0.0% | 0.0% | 4.1% |
| triaged + exemplar envelope | 86.4% | 0.960 | 0.0% / 0.0% | 0.0% | 2.0% |
| triaged + local anomaly threshold | 86.4% | 0.961 | 0.0% / 0.0% | 0.0% | 2.3% |
| triaged + local refit anomaly | 86.4% | 0.960 | 0.0% / 0.0% | 0.0% | 2.1% |
| triaged + two-envelope anomaly | 86.4% | 0.959 | 0.0% / 0.0% | 0.0% | 2.2% |

Lab recall by attack type:

| Variant | FTP-BruteForce | Incomplete-HTTP-Probe | PortScan | SSH-BruteForce | SYN-Burst |
|---|---|---|---|---|---|
| few-shot | 0% | 0% | 100% | 0% | 100% |
| triaged, benchmark anomaly layer | 0% | 0% | 100% | 0% | 100% |
| triaged + exemplar envelope | 0% | 0% | 100% | 0% | 100% |
| triaged + local anomaly threshold | 0% | 0% | 100% | 0% | 100% |
| triaged + local refit anomaly | 0% | 0% | 100% | 0% | 100% |
| triaged + two-envelope anomaly | 0% | 0% | 100% | 0% | 100% |

**Rule R1:** lab recall 86.4% → 86.4% (+0.0 points); retained (threshold −2 points).

## R2. Poisoning the local model of normal

| Fit pool contamination | Variant | Held-out lab recall | Real-network alerts |
|---|---|---|---|
| 0 attacks (0.0%) | triaged + exemplar envelope | 86.4% | 2.0% |
| 10 attacks (0.3%) | triaged + exemplar envelope | 86.4% | 2.0% |
| 30 attacks (0.9%) | triaged + exemplar envelope | 86.4% | 2.0% |
| 100 attacks (2.9%) | triaged + exemplar envelope | 86.4% | 2.0% |
| 264 attacks (7.4%) | triaged + exemplar envelope | 86.4% | 2.0% |
| 0 attacks (0.0%) | triaged + local anomaly threshold | 86.4% | 2.3% |
| 10 attacks (0.3%) | triaged + local anomaly threshold | 86.4% | 2.3% |
| 30 attacks (0.9%) | triaged + local anomaly threshold | 86.4% | 2.3% |
| 100 attacks (2.9%) | triaged + local anomaly threshold | 86.4% | 2.3% |
| 264 attacks (7.4%) | triaged + local anomaly threshold | 86.4% | 2.3% |

Attacks wrongly dismissed as benign during triage (R2), and the same with dismissals gated by the local envelope (R5, exploratory):

| Dismissed attacks | Triage | Dismissals kept (attacks) | Held-out lab recall | FTP-BruteForce | Incomplete-HTTP-Probe | PortScan | SSH-BruteForce | SYN-Burst | Real-network alerts |
|---|---|---|---|---|---|---|---|---|---|
| 0 | — | 30 (0) | 86.4% | 0% | 0% | 100% | 0% | 100% | 2.0% |
| 3 | ungated | 30 (3) | 54.5% | 0% | 0% | 92% | 0% | 26% | 2.0% |
| 3 | gated | 27 (0.0) | 86.4% | 0% | 0% | 100% | 0% | 100% | 2.0% |
| 10 | ungated | 30 (10) | 54.6% | 0% | 0% | 87% | 0% | 33% | 2.1% |
| 10 | gated | 21 (1.2) | 86.4% | 0% | 0% | 100% | 0% | 100% | 2.0% |

## R3. How much local normal traffic is needed?

| Fit pool flows | Variant | Real-network alerts | Lab recall | Benchmark detection |
|---|---|---|---|---|
| 100 | triaged + exemplar envelope | 2.5% | 86.4% | 0.960 |
| 300 | triaged + exemplar envelope | 2.0% | 86.4% | 0.960 |
| 1,000 | triaged + exemplar envelope | 1.8% | 86.4% | 0.960 |
| 3,307 (all) | triaged + exemplar envelope | 2.0% | — | — |
| 100 | triaged + local anomaly threshold | 2.7% | 86.4% | 0.961 |
| 300 | triaged + local anomaly threshold | 2.3% | 86.4% | 0.961 |
| 1,000 | triaged + local anomaly threshold | 2.4% | 86.4% | 0.961 |
| 3,307 (all) | triaged + local anomaly threshold | 2.3% | — | — |

## R4. Evasion: attacks moved toward the nearest local normal flow

| a | few-shot | triaged, benchmark anomaly layer | triaged + exemplar envelope | triaged + local anomaly threshold | Inside the local envelope |
|---|---|---|---|---|---|
| 0.0 | 86.4% | 86.4% | 86.4% | 86.4% | 13.6% |
| 0.2 | 59.9% | 76.3% | 76.3% | 76.3% | 13.6% |
| 0.4 | 25.5% | 43.0% | 43.0% | 43.0% | 14.0% |
| 0.6 | 1.8% | 2.2% | 2.2% | 2.2% | 15.9% |
| 0.8 | 0.6% | 1.7% | 1.7% | 1.7% | 34.6% |
| 0.9 | 0.0% | 1.7% | 1.7% | 1.7% | 70.7% |
| 1.0 | 0.0% | 0.0% | 0.0% | 0.0% | 100.0% |

**Rule R4:** largest gap between the benchmark anomaly layer and the exemplar envelope is 0.0 points; the envelope does not open a new evasion path (threshold 5 points).

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 94.0 min.
