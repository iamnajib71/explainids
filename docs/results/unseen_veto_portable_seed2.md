# Does the local model of normal hide unseen attacks?

Generated on 2026-11-04. LGBM, 79 features (without port and TCP-window features), k = 50, 30 triaged local flows, seed 2. Each attack class is left out of all training in turn; local model of normal fitted on 3,307 flows of an earlier evening. *Anomaly only*: unseen flows that only the benchmark anomaly layer catches. *Vetoed*: of those, how many the local rule removes.

| Unseen class | Test split | Flows | Classifier catches | Anomaly only | Vetoed by exemplar envelope | Vetoed by local threshold |
|---|---|---|---|---|---|---|
| Bot | cicids2017 | 148 | 0.0% | 10 (6.8%) | 0 | 10 |
| Bot | csecicids2018 | 28,585 | 0.4% | 393 (1.4%) | 0 | 393 |
| DDoS-HTTP | cicids2017 | 19,029 | 79.9% | 0 (0.0%) | 0 | 0 |
| DDoS-HTTP | csecicids2018 | 274,325 | 96.7% | 0 (0.0%) | 0 | 0 |
| DDoS-UDP | csecicids2018 | 506 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | cicids2017 | 1,514 | 50.3% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | csecicids2018 | 4,512 | 9.4% | 0 (0.0%) | 0 | 0 |
| DoS-Hulk | cicids2017 | 31,694 | 4.6% | 7 (0.0%) | 0 | 7 |
| DoS-Hulk | csecicids2018 | 360,632 | 0.3% | 0 (0.0%) | 0 | 0 |
| DoS-SlowHTTPTest | cicids2017 | 348 | 52.3% | 0 (0.0%) | 0 | 0 |
| DoS-Slowloris | cicids2017 | 772 | 71.1% | 43 (5.6%) | 43 | 43 |
| DoS-Slowloris | csecicids2018 | 1,698 | 55.0% | 169 (10.0%) | 144 | 169 |
| FTP-BruteForce | cicids2017 | 795 | 0.0% | 0 (0.0%) | 0 | 0 |
| Infiltration | csecicids2018 | 58 | 0.0% | 7 (12.1%) | 6 | 5 |
| PortScan | cicids2017 | 25,485 | 0.3% | 0 (0.0%) | 0 | 0 |
| PortScan | csecicids2018 | 10,309 | 1.1% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | cicids2017 | 593 | 0.0% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | csecicids2018 | 18,840 | 0.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | cicids2017 | 15 | 93.3% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | csecicids2018 | 27 | 96.3% | 0 (0.0%) | 0 | 0 |
| Web-XSS | csecicids2018 | 23 | 100.0% | 0 (0.0%) | 0 | 0 |

**Exemplar envelope:** removes 193 of 629 anomaly-only unseen detections (30.7%); costs novel-attack detection (rule: more than 10%).

**Local anomaly threshold:** removes 627 of 629 anomaly-only unseen detections (99.7%); costs novel-attack detection (rule: more than 10%).

Real-network false-alert rate on the later evening, mean over the leave-one-out models: benchmark anomaly layer 3.8%; exemplar envelope 1.6%; local anomaly threshold 1.9%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 17.4 min.
