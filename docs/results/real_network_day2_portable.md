# Real-network evaluation

Generated on 2026-11-02. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 4,634 flows in 12 capture blocks (0.99 h of observed traffic) from a network in ordinary use. Local training flows come only from 12 sessions recorded on an earlier day (3307 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.307 | 5.4% | 3.8%–7.0% | 251 |
| source only + local anomaly threshold | 0.304 | 3.8% | 2.5%–5.0% | 175 |
| source only + two-envelope anomaly | 0.303 | 3.8% | 2.5%–5.2% | 176 |
| source only + exemplar envelope | 0.303 | 3.7% | 2.4%–5.0% | 173 |
| source only + local refit anomaly | 0.303 | 3.6% | 2.3%–4.9% | 167 |
| both environments | 0.982 | 5.0% | 3.7%–6.3% | 235 |
| few-shot | 0.962 | 6.6% (seeds 6.4%–7.0%) | 4.4%–8.9% | 310 |
| few-shot + 30 lab service flows | 0.961 | 6.5% (seeds 6.0%–7.2%) | 4.3%–8.8% | 305 |
| few-shot + 30 local flows | 0.959 | 5.4% (seeds 3.9%–6.5%) | 2.9%–7.8% | 251 |
| few-shot + 30 triaged local flows | 0.961 | 4.1% (seeds 3.7%–5.1%) | 2.4%–6.8% | 191 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.961 | 2.3% (seeds 2.0%–3.3%) | 1.1%–4.6% | 107 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.959 | 2.2% (seeds 1.9%–3.2%) | 0.9%–4.8% | 104 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.960 | 2.0% (seeds 1.7%–3.1%) | 0.9%–4.5% | 94 |
| few-shot + 30 triaged local flows + local refit anomaly | 0.960 | 2.1% (seeds 1.8%–3.2%) | 1.0%–4.5% | 100 |
| few-shot + 30 uncertain local flows | 0.958 | 6.2% (seeds 5.4%–6.9%) | 3.8%–8.7% | 288 |
| few-shot + 30 uncertain local flows + exemplar envelope | 0.957 | 4.3% (seeds 3.7%–5.0%) | 2.5%–6.6% | 202 |
| source only + 30 local flows | 0.305 | 4.9% (seeds 4.7%–5.0%) | 3.4%–6.4% | 229 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/249) | 443: 81, 1900: 49, 5353: 20, 0: 10, 5351: 8, 13246: 6 | DoS-SlowHTTPTest: 75, Infiltration: 29, PortScan: 28, Heartbleed: 6, SSH-BruteForce: 4 |
| source only + local anomaly threshold | 0% (0/174) | 1900: 48, 443: 34, 0: 10, 5351: 8, 13246: 6, 2710: 5 | DoS-SlowHTTPTest: 75, Infiltration: 29, PortScan: 28, Heartbleed: 6, SSH-BruteForce: 4 |
| source only + two-envelope anomaly | 0% (0/175) | 1900: 48, 443: 38, 0: 10, 5351: 8, 13246: 6, 2710: 5 | DoS-SlowHTTPTest: 75, Infiltration: 29, PortScan: 28, Heartbleed: 6, SSH-BruteForce: 4 |
| source only + exemplar envelope | 0% (0/172) | 1900: 48, 443: 34, 0: 10, 5351: 8, 13246: 6, 2710: 5 | DoS-SlowHTTPTest: 75, Infiltration: 29, PortScan: 28, Heartbleed: 6, SSH-BruteForce: 4 |
| source only + local refit anomaly | 0% (0/166) | 1900: 48, 443: 27, 0: 10, 5351: 8, 13246: 6, 2710: 5 | DoS-SlowHTTPTest: 75, Infiltration: 29, PortScan: 28, Heartbleed: 6, SSH-BruteForce: 4 |
| both environments | 7% (16/233) | 443: 115, 5353: 25, 5351: 16, 53: 15, 4749: 6, 13246: 6 | PortScan: 55, Infiltration: 18, FTP-BruteForce: 8, DDoS-HTTP: 6, Bot: 4 |
| few-shot | 3% (43/1540) | 443: 468, 1900: 356, 53: 97, 5353: 81, 5351: 65, 0: 41 | PortScan: 648, Infiltration: 183, Bot: 93, FTP-BruteForce: 29, DoS-SlowHTTPTest: 27 |
| few-shot + 30 lab service flows | 4% (59/1515) | 443: 481, 1900: 336, 5353: 83, 5351: 70, 0: 57, 53: 51 | PortScan: 653, Infiltration: 192, Bot: 45, FTP-BruteForce: 41, DoS-SlowHTTPTest: 29 |
| few-shot + 30 local flows | 0% (0/1248) | 443: 480, 1900: 190, 53: 82, 5353: 79, 0: 43, 4749: 33 | PortScan: 372, Infiltration: 176, Bot: 76, FTP-BruteForce: 32, DoS-SlowHTTPTest: 28 |
| few-shot + 30 triaged local flows | 0% (0/949) | 443: 475, 53: 109, 5353: 77, 4749: 32, 13246: 30, 2710: 25 | PortScan: 104, Bot: 103, Infiltration: 52, FTP-BruteForce: 27, DoS-SlowHTTPTest: 15 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0% (0/530) | 443: 206, 53: 109, 13246: 30, 2710: 25, 0: 22, 10004: 20 | PortScan: 104, Bot: 103, Infiltration: 52, FTP-BruteForce: 27, DoS-SlowHTTPTest: 15 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0% (0/515) | 443: 239, 53: 109, 0: 22, 13246: 20, 10004: 15, 2710: 15 | PortScan: 104, Bot: 103, Infiltration: 52, FTP-BruteForce: 27, DoS-SlowHTTPTest: 15 |
| few-shot + 30 triaged local flows + exemplar envelope | 0% (0/469) | 443: 226, 53: 109, 0: 22, 4749: 15, 80: 11, 5351: 10 | PortScan: 104, Bot: 103, Infiltration: 52, FTP-BruteForce: 27, DoS-SlowHTTPTest: 15 |
| few-shot + 30 triaged local flows + local refit anomaly | 0% (0/495) | 443: 184, 53: 109, 13246: 30, 2710: 25, 0: 22, 10004: 20 | PortScan: 104, Bot: 103, Infiltration: 52, FTP-BruteForce: 27, DoS-SlowHTTPTest: 15 |
| few-shot + 30 uncertain local flows | 2% (30/1429) | 443: 464, 1900: 293, 53: 88, 5353: 85, 0: 46, 5351: 40 | PortScan: 517, Infiltration: 157, DoS-SlowHTTPTest: 89, Bot: 79, Heartbleed: 5 |
| few-shot + 30 uncertain local flows + exemplar envelope | 3% (30/1001) | 1900: 288, 443: 201, 53: 88, 0: 46, 5351: 40, 13246: 23 | PortScan: 517, Infiltration: 157, DoS-SlowHTTPTest: 89, Bot: 79, Heartbleed: 5 |
| source only + 30 local flows | 0% (0/1138) | 443: 375, 1900: 233, 5353: 100, 13246: 30, 0: 27, 2710: 25 | DoS-SlowHTTPTest: 380, Infiltration: 155, PortScan: 57, Heartbleed: 28, SSH-BruteForce: 14 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 67.0 min.
