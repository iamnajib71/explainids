# The two lab attack types every variant misses

Generated on 2026-11-07. 79 features (without port and TCP-window features); seeds 42, 1, 2, 3, 4; labelled examples from run_20261025T050509Z, recall on the other two replicates (FTP-BruteForce: 24, Incomplete-HTTP-Probe: 24 flows); 660 benign service-profile flows. Rules in the script docstring.

## D. Can the features see them?

| Attack type | In 2017 / 2018 training | Lab-only recall (leave one replicate out) | Lab-only benign FPR | Nearest training flow | Deployed model predicts | Verdict |
|---|---|---|---|---|---|---|
| FTP-BruteForce | yes / no | 1.00 | 16.9% | BENIGN 100% | BENIGN 36 | **features cannot separate it** |
| Incomplete-HTTP-Probe | no / no | 1.00 | 0.0% | BENIGN 100% | BENIGN 36 | **features can see it** |

## F. Do a few labels fix it?

| Labelled flows per type (k) | FTP-BruteForce recall | Incomplete-HTTP-Probe recall | Benign profile false alerts | Real-network alerts | Benchmark detection |
|---|---|---|---|---|---|
| 0 | 0.00 | 0.00 | 20.6% | 2.0% | 0.960 |
| 3 | 1.00 | 0.98 | 18.4% | 1.9% | 0.965 |
| 12 | 1.00 | 0.98 | 22.8% | 2.0% | 0.964 |

**FTP-BruteForce:** k = 12 gives recall 1.00 (from 0.00); profile false alerts 20.6% → 22.8%, real-network 2.0% → 2.0%: **not fixed** under the rule.

**Incomplete-HTTP-Probe:** k = 12 gives recall 0.98 (from 0.00); profile false alerts 20.6% → 22.8%, real-network 2.0% → 2.0%: **not fixed** under the rule.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 30.6 min.
