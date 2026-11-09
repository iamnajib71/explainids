# Real-network evaluation

Generated on 2026-11-09. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 4,117 flows in 12 capture blocks (0.99 h of observed traffic) from a network in ordinary use. Local training flows come only from 12 sessions recorded on an earlier day (3307 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.307 | 3.8% | 2.5%–4.7% | 158 |
| source only + local anomaly threshold | 0.304 | 1.9% | 1.0%–2.5% | 78 |
| source only + two-envelope anomaly | 0.303 | 1.9% | 1.1%–2.5% | 79 |
| source only + exemplar envelope | 0.303 | 1.8% | 1.0%–2.3% | 75 |
| source only + local refit anomaly | 0.303 | 1.8% | 1.0%–2.4% | 75 |
| both environments | 0.982 | 4.1% | 2.6%–5.1% | 170 |
| few-shot | 0.962 | 5.2% (seeds 4.8%–5.7%) | 2.8%–7.3% | 215 |
| few-shot + 30 lab service flows | 0.961 | 4.7% (seeds 4.0%–5.3%) | 2.9%–6.4% | 196 |
| few-shot + 30 local flows | 0.959 | 4.6% (seeds 3.9%–5.1%) | 2.2%–6.5% | 191 |
| few-shot + 30 triaged local flows | 0.961 | 4.2% (seeds 3.9%–4.9%) | 1.8%–6.5% | 173 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.961 | 2.4% (seeds 2.0%–3.1%) | 0.9%–4.3% | 100 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.959 | 2.3% (seeds 1.9%–3.1%) | 0.9%–4.2% | 96 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.960 | 2.2% (seeds 1.8%–2.9%) | 0.9%–4.0% | 90 |
| few-shot + 30 triaged local flows + local refit anomaly | 0.960 | 2.3% (seeds 1.9%–3.1%) | 0.9%–4.2% | 96 |
| few-shot + 30 uncertain local flows | 0.958 | 4.6% (seeds 3.9%–5.0%) | 2.1%–6.5% | 192 |
| few-shot + 30 uncertain local flows + exemplar envelope | 0.957 | 2.8% (seeds 2.2%–3.2%) | 1.1%–4.1% | 116 |
| source only + 30 local flows | 0.305 | 3.6% (seeds 3.5%–3.7%) | 2.3%–4.6% | 149 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/156) | 443: 68, 5353: 13, 0: 9, 9683: 8, 5972: 6, 4649: 4 | Infiltration: 28, PortScan: 18, DoS-SlowHTTPTest: 15, DoS-GoldenEye: 4, FTP-BruteForce: 2 |
| source only + local anomaly threshold | 0% (0/77) | 443: 15, 0: 9, 9683: 8, 5972: 5, 13184: 4, 13259: 3 | Infiltration: 28, PortScan: 18, DoS-SlowHTTPTest: 15, DoS-GoldenEye: 4, FTP-BruteForce: 2 |
| source only + two-envelope anomaly | 0% (0/78) | 443: 17, 0: 9, 9683: 8, 5972: 5, 13184: 4, 13259: 3 | Infiltration: 28, PortScan: 18, DoS-SlowHTTPTest: 15, DoS-GoldenEye: 4, FTP-BruteForce: 2 |
| source only + exemplar envelope | 0% (0/74) | 443: 11, 0: 9, 9683: 8, 5972: 5, 4649: 4, 13184: 4 | Infiltration: 28, PortScan: 18, DoS-SlowHTTPTest: 15, DoS-GoldenEye: 4, FTP-BruteForce: 2 |
| source only + local refit anomaly | 0% (0/74) | 443: 13, 0: 9, 9683: 8, 5972: 5, 13184: 4, 13259: 3 | Infiltration: 28, PortScan: 18, DoS-SlowHTTPTest: 15, DoS-GoldenEye: 4, FTP-BruteForce: 2 |
| both environments | 4% (6/168) | 443: 75, 5353: 22, 53: 20, 68: 6, 67: 4, 13259: 3 | PortScan: 30, Infiltration: 21, Bot: 12, DoS-SlowHTTPTest: 2, DoS-GoldenEye: 1 |
| few-shot | 2% (16/1064) | 443: 360, 53: 226, 1900: 111, 5353: 29, 5972: 28, 0: 27 | Bot: 226, PortScan: 194, Infiltration: 176, DoS-SlowHTTPTest: 73, SSH-BruteForce: 7 |
| few-shot + 30 lab service flows | 1% (5/968) | 443: 361, 53: 117, 1900: 99, 0: 39, 5353: 29, 5972: 29 | PortScan: 208, Infiltration: 167, Bot: 119, DoS-SlowHTTPTest: 68, SSH-BruteForce: 7 |
| few-shot + 30 local flows | 1% (5/944) | 443: 364, 53: 181, 1900: 45, 0: 29, 9683: 29, 5972: 29 | Bot: 181, Infiltration: 161, PortScan: 122, DoS-SlowHTTPTest: 76, Web-BruteForce: 6 |
| few-shot + 30 triaged local flows | 0% (0/858) | 443: 346, 53: 234, 5353: 25, 5972: 22, 0: 18, 9683: 14 | Bot: 234, PortScan: 65, Infiltration: 65, DoS-SlowHTTPTest: 46, FTP-BruteForce: 6 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0% (0/496) | 53: 234, 443: 77, 0: 18, 2122: 15, 9683: 14, 5972: 12 | Bot: 234, PortScan: 65, Infiltration: 65, DoS-SlowHTTPTest: 46, FTP-BruteForce: 6 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0% (0/477) | 53: 234, 443: 87, 0: 18, 9683: 14, 5972: 12, 13259: 12 | Bot: 234, PortScan: 65, Infiltration: 65, DoS-SlowHTTPTest: 46, FTP-BruteForce: 6 |
| few-shot + 30 triaged local flows + exemplar envelope | 0% (0/447) | 53: 234, 443: 59, 0: 18, 9683: 14, 5972: 12, 13259: 12 | Bot: 234, PortScan: 65, Infiltration: 65, DoS-SlowHTTPTest: 46, FTP-BruteForce: 6 |
| few-shot + 30 triaged local flows + local refit anomaly | 0% (0/475) | 53: 234, 443: 67, 0: 18, 2122: 15, 9683: 14, 5972: 12 | Bot: 234, PortScan: 65, Infiltration: 65, DoS-SlowHTTPTest: 46, FTP-BruteForce: 6 |
| few-shot + 30 uncertain local flows | 1% (10/949) | 443: 346, 53: 192, 1900: 57, 0: 34, 5353: 29, 5972: 29 | Bot: 192, Infiltration: 156, PortScan: 121, DoS-SlowHTTPTest: 74, FTP-BruteForce: 1 |
| few-shot + 30 uncertain local flows + exemplar envelope | 2% (10/572) | 53: 192, 1900: 53, 443: 41, 0: 34, 9683: 28, 5972: 25 | Bot: 192, Infiltration: 156, PortScan: 121, DoS-SlowHTTPTest: 74, FTP-BruteForce: 1 |
| source only + 30 local flows | 0% (0/737) | 443: 322, 5353: 67, 9683: 39, 5972: 27, 4649: 20, 13184: 20 | Infiltration: 140, DoS-SlowHTTPTest: 73, PortScan: 58, DoS-GoldenEye: 20, FTP-BruteForce: 10 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 69.1 min.
