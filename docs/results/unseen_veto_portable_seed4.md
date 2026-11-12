# Does the local model of normal hide unseen attacks?

Generated on 2026-11-04. LGBM, 79 features (without port and TCP-window features), k = 50, 30 triaged local flows, seed 4. Each attack class is left out of all training in turn; local model of normal fitted on 3,307 flows of an earlier evening. *Anomaly only*: unseen flows that only the benchmark anomaly layer catches. *Vetoed*: of those, how many the local rule removes.

| Unseen class | Test split | Flows | Classifier catches | Anomaly only | Vetoed by exemplar envelope | Vetoed by local threshold |
|---|---|---|---|---|---|---|
| Bot | cicids2017 | 148 | 0.0% | 9 (6.1%) | 0 | 9 |
| Bot | csecicids2018 | 28,585 | 0.8% | 393 (1.4%) | 0 | 380 |
| DDoS-HTTP | cicids2017 | 19,029 | 87.6% | 0 (0.0%) | 0 | 0 |
| DDoS-HTTP | csecicids2018 | 274,325 | 98.9% | 0 (0.0%) | 0 | 0 |
| DDoS-UDP | csecicids2018 | 506 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | cicids2017 | 1,514 | 74.1% | 1 (0.1%) | 0 | 1 |
| DoS-GoldenEye | csecicids2018 | 4,512 | 5.4% | 0 (0.0%) | 0 | 0 |
| DoS-Hulk | cicids2017 | 31,694 | 4.8% | 6 (0.0%) | 0 | 6 |
| DoS-Hulk | csecicids2018 | 360,632 | 2.1% | 0 (0.0%) | 0 | 0 |
| DoS-SlowHTTPTest | cicids2017 | 348 | 55.5% | 2 (0.6%) | 0 | 2 |
| DoS-Slowloris | cicids2017 | 772 | 53.9% | 110 (14.2%) | 43 | 110 |
| DoS-Slowloris | csecicids2018 | 1,698 | 47.2% | 167 (9.8%) | 151 | 167 |
| FTP-BruteForce | cicids2017 | 795 | 0.0% | 0 (0.0%) | 0 | 0 |
| Infiltration | csecicids2018 | 58 | 0.0% | 8 (13.8%) | 7 | 6 |
| PortScan | cicids2017 | 25,485 | 0.1% | 0 (0.0%) | 0 | 0 |
| PortScan | csecicids2018 | 10,309 | 0.5% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | cicids2017 | 593 | 0.0% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | csecicids2018 | 18,840 | 0.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | cicids2017 | 15 | 93.3% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | csecicids2018 | 27 | 96.3% | 0 (0.0%) | 0 | 0 |
| Web-XSS | csecicids2018 | 23 | 95.7% | 0 (0.0%) | 0 | 0 |

**Exemplar envelope:** removes 201 of 696 anomaly-only unseen detections (28.9%); costs novel-attack detection (rule: more than 10%).

**Local anomaly threshold:** removes 681 of 696 anomaly-only unseen detections (97.8%); costs novel-attack detection (rule: more than 10%).

Real-network false-alert rate on the later evening, mean over the leave-one-out models: benchmark anomaly layer 4.0%; exemplar envelope 1.8%; local anomaly threshold 2.1%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 19.2 min.
