# Does the local model of normal hide unseen attacks?

Generated on 2026-11-04. LGBM, 83 features (all features), k = 50, 30 triaged local flows, seed 1. Each attack class is left out of all training in turn; local model of normal fitted on 3,307 flows of an earlier evening. *Anomaly only*: unseen flows that only the benchmark anomaly layer catches. *Vetoed*: of those, how many the local rule removes.

| Unseen class | Test split | Flows | Classifier catches | Anomaly only | Vetoed by exemplar envelope | Vetoed by local threshold |
|---|---|---|---|---|---|---|
| Bot | cicids2017 | 148 | 0.0% | 10 (6.8%) | 0 | 10 |
| Bot | csecicids2018 | 28,585 | 0.0% | 393 (1.4%) | 0 | 376 |
| DDoS-HTTP | cicids2017 | 19,029 | 94.4% | 0 (0.0%) | 0 | 0 |
| DDoS-HTTP | csecicids2018 | 274,325 | 90.1% | 0 (0.0%) | 0 | 0 |
| DDoS-UDP | csecicids2018 | 506 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | cicids2017 | 1,514 | 44.6% | 1 (0.1%) | 0 | 1 |
| DoS-GoldenEye | csecicids2018 | 4,512 | 28.3% | 0 (0.0%) | 0 | 0 |
| DoS-Hulk | cicids2017 | 31,694 | 5.6% | 2 (0.0%) | 0 | 2 |
| DoS-Hulk | csecicids2018 | 360,632 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-SlowHTTPTest | cicids2017 | 348 | 54.3% | 0 (0.0%) | 0 | 0 |
| DoS-Slowloris | cicids2017 | 772 | 74.0% | 0 (0.0%) | 0 | 0 |
| DoS-Slowloris | csecicids2018 | 1,698 | 62.4% | 0 (0.0%) | 0 | 0 |
| FTP-BruteForce | cicids2017 | 795 | 0.0% | 0 (0.0%) | 0 | 0 |
| Infiltration | csecicids2018 | 58 | 0.0% | 8 (13.8%) | 6 | 7 |
| PortScan | cicids2017 | 25,485 | 0.2% | 0 (0.0%) | 0 | 0 |
| PortScan | csecicids2018 | 10,309 | 0.1% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | cicids2017 | 593 | 0.0% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | csecicids2018 | 18,840 | 0.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | cicids2017 | 15 | 100.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | csecicids2018 | 27 | 100.0% | 0 (0.0%) | 0 | 0 |
| Web-XSS | csecicids2018 | 23 | 100.0% | 0 (0.0%) | 0 | 0 |

**Exemplar envelope:** removes 6 of 414 anomaly-only unseen detections (1.4%); within the 10% rule.

**Local anomaly threshold:** removes 396 of 414 anomaly-only unseen detections (95.7%); costs novel-attack detection (rule: more than 10%).

Real-network false-alert rate on the later evening, mean over the leave-one-out models: benchmark anomaly layer 2.7%; exemplar envelope 1.1%; local anomaly threshold 1.2%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 18.5 min.
