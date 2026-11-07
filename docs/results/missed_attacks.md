# The two lab attack types every variant misses

Generated on 2026-11-07. 83 features (all features); seeds 42, 1, 2, 3, 4; labelled examples from run_20261025T050509Z, recall on the other two replicates (FTP-BruteForce: 24, Incomplete-HTTP-Probe: 24 flows); 660 benign service-profile flows. Rules in the script docstring.

## D. Can the features see them?

| Attack type | In 2017 / 2018 training | Lab-only recall (leave one replicate out) | Lab-only benign FPR | Nearest training flow | Deployed model predicts | Verdict |
|---|---|---|---|---|---|---|
| FTP-BruteForce | yes / no | 1.00 | 9.0% | BENIGN 100% | BENIGN 36 | **features cannot separate it** |
| Incomplete-HTTP-Probe | no / no | 1.00 | 0.0% | BENIGN 100% | BENIGN 36 | **features can see it** |

## F. Do a few labels fix it?

| Labelled flows per type (k) | FTP-BruteForce recall | Incomplete-HTTP-Probe recall | Benign profile false alerts | Real-network alerts | Benchmark detection |
|---|---|---|---|---|---|
| 0 | 0.00 | 0.00 | 42.1% | 1.0% | 0.981 |
| 3 | 1.00 | 1.00 | 52.4% | 1.0% | 0.983 |
| 12 | 1.00 | 1.00 | 54.2% | 1.1% | 0.982 |

**FTP-BruteForce:** k = 12 gives recall 1.00 (from 0.00); profile false alerts 42.1% → 54.2%, real-network 1.0% → 1.1%: **not fixed** under the rule.

**Incomplete-HTTP-Probe:** k = 12 gives recall 1.00 (from 0.00); profile false alerts 42.1% → 54.2%, real-network 1.0% → 1.1%: **not fixed** under the rule.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 39.0 min.
