# Real-network evaluation

Generated on 2026-11-01. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 3,307 flows in 12 capture blocks (0.93 h of observed traffic) from a network in ordinary use. Local training flows come only from 2 sessions recorded on an earlier day (222 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.307 | 5.4% | 3.2%–7.6% | 192 |
| source only + local anomaly threshold | 0.303 | 2.4% | 0.6%–4.3% | 85 |
| source only + two-envelope anomaly | 0.307 | 5.0% | 2.9%–7.1% | 176 |
| source only + exemplar envelope | 0.303 | 2.5% | 0.8%–4.3% | 88 |
| source only + local refit anomaly | 0.304 | 4.1% | 1.9%–6.2% | 147 |
| both environments | 0.982 | 5.7% | 4.3%–6.9% | 200 |
| few-shot | 0.962 | 6.9% (seeds 6.0%–7.6%) | 3.8%–10.2% | 243 |
| few-shot + 30 lab service flows | 0.961 | 7.0% (seeds 6.8%–7.6%) | 4.2%–10.1% | 250 |
| few-shot + 30 local flows | 0.960 | 5.2% (seeds 4.7%–5.6%) | 3.3%–6.7% | 186 |
| few-shot + 30 triaged local flows | 0.960 | 5.2% (seeds 5.0%–5.7%) | 3.5%–6.7% | 186 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.958 | 2.1% (seeds 1.8%–2.3%) | 1.0%–2.8% | 73 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.960 | 4.7% (seeds 4.5%–5.0%) | 3.1%–5.9% | 165 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.958 | 2.0% (seeds 1.9%–2.2%) | 1.0%–2.7% | 72 |
| few-shot + 30 triaged local flows + local refit anomaly | 0.959 | 3.8% (seeds 3.7%–4.0%) | 2.2%–4.8% | 135 |
| few-shot + 30 uncertain local flows | 0.959 | 5.2% (seeds 4.8%–6.4%) | 3.4%–9.2% | 185 |
| few-shot + 30 uncertain local flows + exemplar envelope | 0.957 | 2.2% (seeds 1.7%–3.2%) | 1.1%–5.6% | 78 |
| source only + 30 local flows | 0.308 | 4.4% (seeds 4.0%–4.9%) | 3.0%–6.1% | 155 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/179) | 443: 85, 5353: 17, 5351: 9, 0: 5, 55490: 4, 57449: 4 | DoS-SlowHTTPTest: 34, Infiltration: 17, PortScan: 15, Heartbleed: 3, FTP-BruteForce: 1 |
| source only + local anomaly threshold | 0% (0/79) | 443: 11, 5351: 9, 0: 5, 55490: 4, 57449: 4, 58754: 4 | DoS-SlowHTTPTest: 34, Infiltration: 17, PortScan: 15, Heartbleed: 3, FTP-BruteForce: 1 |
| source only + two-envelope anomaly | 0% (0/164) | 443: 73, 5353: 16, 5351: 9, 0: 5, 55490: 4, 57449: 4 | DoS-SlowHTTPTest: 34, Infiltration: 17, PortScan: 15, Heartbleed: 3, FTP-BruteForce: 1 |
| source only + exemplar envelope | 0% (0/82) | 443: 10, 5351: 9, 5353: 6, 0: 5, 55490: 4, 57449: 4 | DoS-SlowHTTPTest: 34, Infiltration: 17, PortScan: 15, Heartbleed: 3, FTP-BruteForce: 1 |
| source only + local refit anomaly | 0% (0/137) | 443: 63, 5351: 9, 0: 5, 55490: 4, 57449: 4, 58754: 4 | DoS-SlowHTTPTest: 34, Infiltration: 17, PortScan: 15, Heartbleed: 3, FTP-BruteForce: 1 |
| both environments | 20% (38/187) | 443: 101, 5351: 24, 5353: 22, 67: 7, 68: 7, 63492: 4 | PortScan: 42, Infiltration: 17, FTP-BruteForce: 3, Heartbleed: 2, Bot: 1 |
| few-shot | 6% (64/1133) | 443: 478, 1900: 90, 5351: 88, 5353: 78, 0: 25, 63492: 25 | PortScan: 408, Infiltration: 108, SSH-BruteForce: 33, FTP-BruteForce: 15, Heartbleed: 9 |
| few-shot + 30 lab service flows | 7% (86/1165) | 443: 485, 5351: 102, 5353: 78, 1900: 78, 0: 38, 63492: 25 | PortScan: 439, Infiltration: 105, SSH-BruteForce: 33, FTP-BruteForce: 17, Web-BruteForce: 9 |
| few-shot + 30 local flows | 0% (0/867) | 443: 485, 5353: 77, 5351: 74, 0: 30, 63492: 25, 9026: 20 | PortScan: 151, Infiltration: 75, SSH-BruteForce: 37, FTP-BruteForce: 15, Heartbleed: 7 |
| few-shot + 30 triaged local flows | 0% (0/868) | 443: 478, 5353: 76, 5351: 70, 0: 36, 63492: 25, 9026: 20 | PortScan: 134, Infiltration: 83, SSH-BruteForce: 32, FTP-BruteForce: 13, Heartbleed: 5 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0% (0/341) | 443: 82, 5351: 70, 0: 36, 9026: 19, 6239: 15, 12178: 11 | PortScan: 134, Infiltration: 83, SSH-BruteForce: 32, FTP-BruteForce: 13, Heartbleed: 5 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0% (0/771) | 443: 410, 5353: 71, 5351: 70, 0: 36, 9026: 20, 63492: 15 | PortScan: 134, Infiltration: 83, SSH-BruteForce: 32, FTP-BruteForce: 13, Heartbleed: 5 |
| few-shot + 30 triaged local flows + exemplar envelope | 0% (0/335) | 443: 74, 5351: 70, 0: 36, 5353: 29, 12178: 11, 6239: 11 | PortScan: 134, Infiltration: 83, SSH-BruteForce: 32, FTP-BruteForce: 13, Heartbleed: 5 |
| few-shot + 30 triaged local flows + local refit anomaly | 0% (0/632) | 443: 341, 5351: 70, 0: 36, 9026: 20, 12178: 15, 6239: 15 | PortScan: 134, Infiltration: 83, SSH-BruteForce: 32, FTP-BruteForce: 13, Heartbleed: 5 |
| few-shot + 30 uncertain local flows | 4% (35/865) | 443: 431, 5351: 77, 5353: 76, 0: 40, 63492: 25, 9026: 16 | PortScan: 184, Infiltration: 76, SSH-BruteForce: 24, Heartbleed: 6, DoS-SlowHTTPTest: 6 |
| few-shot + 30 uncertain local flows + exemplar envelope | 9% (33/362) | 5351: 77, 443: 50, 0: 40, 5353: 29, 1900: 11, 67: 10 | PortScan: 184, Infiltration: 76, SSH-BruteForce: 24, Heartbleed: 6, DoS-SlowHTTPTest: 6 |
| source only + 30 local flows | 0% (0/723) | 443: 421, 5353: 85, 0: 34, 9026: 20, 5351: 15, 63492: 12 | Infiltration: 68, PortScan: 51, DoS-SlowHTTPTest: 37, Heartbleed: 16, FTP-BruteForce: 5 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 77.8 min.
