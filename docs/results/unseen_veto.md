# Does the local model of normal hide unseen attacks?

Generated on 2026-11-03. LGBM, 83 features (all features), k = 50, 30 triaged local flows, seed 42. Each attack class is left out of all training in turn; local model of normal fitted on 3,307 flows of an earlier evening. *Anomaly only*: unseen flows that only the benchmark anomaly layer catches. *Vetoed*: of those, how many the local rule removes.

| Unseen class | Test split | Flows | Classifier catches | Anomaly only | Vetoed by exemplar envelope | Vetoed by local threshold |
|---|---|---|---|---|---|---|
| Bot | cicids2017 | 148 | 0.0% | 10 (6.8%) | 0 | 8 |
| Bot | csecicids2018 | 28,585 | 0.0% | 393 (1.4%) | 0 | 249 |
| DDoS-HTTP | cicids2017 | 19,029 | 95.8% | 0 (0.0%) | 0 | 0 |
| DDoS-HTTP | csecicids2018 | 274,325 | 86.0% | 0 (0.0%) | 0 | 0 |
| DDoS-UDP | csecicids2018 | 506 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | cicids2017 | 1,514 | 69.0% | 0 (0.0%) | 0 | 0 |
| DoS-GoldenEye | csecicids2018 | 4,512 | 25.0% | 0 (0.0%) | 0 | 0 |
| DoS-Hulk | cicids2017 | 31,694 | 6.4% | 2 (0.0%) | 0 | 2 |
| DoS-Hulk | csecicids2018 | 360,632 | 0.0% | 0 (0.0%) | 0 | 0 |
| DoS-SlowHTTPTest | cicids2017 | 348 | 55.7% | 0 (0.0%) | 0 | 0 |
| DoS-Slowloris | cicids2017 | 772 | 74.7% | 42 (5.4%) | 42 | 42 |
| DoS-Slowloris | csecicids2018 | 1,698 | 64.5% | 144 (8.5%) | 144 | 144 |
| FTP-BruteForce | cicids2017 | 795 | 0.0% | 0 (0.0%) | 0 | 0 |
| Infiltration | csecicids2018 | 58 | 0.0% | 8 (13.8%) | 6 | 7 |
| PortScan | cicids2017 | 25,485 | 0.2% | 0 (0.0%) | 0 | 0 |
| PortScan | csecicids2018 | 10,309 | 0.1% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | cicids2017 | 593 | 0.0% | 0 (0.0%) | 0 | 0 |
| SSH-BruteForce | csecicids2018 | 18,840 | 0.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | cicids2017 | 15 | 100.0% | 0 (0.0%) | 0 | 0 |
| Web-BruteForce | csecicids2018 | 27 | 96.3% | 0 (0.0%) | 0 | 0 |
| Web-XSS | csecicids2018 | 23 | 100.0% | 0 (0.0%) | 0 | 0 |

**Exemplar envelope:** removes 192 of 599 anomaly-only unseen detections (32.1%); costs novel-attack detection (rule: more than 10%).

**Local anomaly threshold:** removes 452 of 599 anomaly-only unseen detections (75.5%); costs novel-attack detection (rule: more than 10%).

Real-network false-alert rate on the later evening, mean over the leave-one-out models: benchmark anomaly layer 2.8%; exemplar envelope 1.1%; local anomaly threshold 1.3%.

Accuracy is not reported (rule 4). No addresses or per-flow records.

Total run time 19.8 min.
