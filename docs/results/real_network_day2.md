# Real-network evaluation

Generated on 2026-11-02. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 4,634 flows in 12 capture blocks (0.99 h of observed traffic) from a network in ordinary use. Local training flows come only from 12 sessions recorded on an earlier day (3307 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.548 | 5.1% | 3.7%–6.7% | 238 |
| source only + local anomaly threshold | 0.546 | 3.6% | 2.5%–5.0% | 169 |
| source only + two-envelope anomaly | 0.546 | 3.6% | 2.4%–5.0% | 167 |
| source only + exemplar envelope | 0.548 | 3.7% | 2.5%–5.2% | 174 |
| source only + local refit anomaly | 0.546 | 3.5% | 2.4%–4.9% | 163 |
| both environments | 0.996 | 5.4% | 3.4%–7.5% | 254 |
| few-shot | 0.980 | 6.2% (seeds 5.8%–7.2%) | 4.2%–8.9% | 290 |
| few-shot + 30 lab service flows | 0.982 | 6.4% (seeds 5.8%–7.9%) | 4.2%–9.5% | 300 |
| few-shot + 30 local flows | 0.981 | 4.5% (seeds 3.4%–5.1%) | 2.0%–6.3% | 209 |
| few-shot + 30 triaged local flows | 0.981 | 2.9% (seeds 2.7%–3.1%) | 1.9%–3.8% | 133 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.980 | 1.3% (seeds 1.2%–1.3%) | 0.7%–1.9% | 58 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.980 | 0.9% (seeds 0.8%–0.9%) | 0.3%–1.5% | 41 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.981 | 1.0% (seeds 0.9%–1.0%) | 0.4%–1.7% | 46 |
| few-shot + 30 triaged local flows + local refit anomaly | 0.980 | 0.9% (seeds 0.8%–0.9%) | 0.4%–1.5% | 41 |
| few-shot + 30 uncertain local flows | 0.980 | 5.5% (seeds 5.2%–5.9%) | 3.9%–7.6% | 257 |
| few-shot + 30 uncertain local flows + exemplar envelope | 0.980 | 4.0% (seeds 3.5%–4.7%) | 2.5%–6.3% | 188 |
| source only + 30 local flows | 0.555 | 4.5% (seeds 3.6%–4.9%) | 2.2%–6.3% | 209 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/236) | 443: 73, 1900: 49, 5351: 8, 5353: 8, 0: 8, 4749: 6 | PortScan: 91, Infiltration: 38, DoS-SlowHTTPTest: 13, Bot: 2, Heartbleed: 2 |
| source only + local anomaly threshold | 0% (0/168) | 1900: 48, 443: 19, 5351: 8, 0: 8, 13246: 6, 2710: 5 | PortScan: 91, Infiltration: 38, DoS-SlowHTTPTest: 13, Bot: 2, Heartbleed: 2 |
| source only + two-envelope anomaly | 0% (0/166) | 1900: 48, 443: 17, 5351: 8, 0: 8, 13246: 6, 2710: 5 | PortScan: 91, Infiltration: 38, DoS-SlowHTTPTest: 13, Bot: 2, Heartbleed: 2 |
| source only + exemplar envelope | 0% (0/173) | 1900: 48, 443: 25, 5351: 8, 0: 8, 13246: 6, 2710: 5 | PortScan: 91, Infiltration: 38, DoS-SlowHTTPTest: 13, Bot: 2, Heartbleed: 2 |
| source only + local refit anomaly | 0% (0/162) | 1900: 48, 443: 13, 5351: 8, 0: 8, 13246: 6, 2710: 5 | PortScan: 91, Infiltration: 38, DoS-SlowHTTPTest: 13, Bot: 2, Heartbleed: 2 |
| both environments | 6% (16/252) | 443: 156, 5351: 16, 13246: 6, 5353: 5, 2710: 5, 10004: 4 | PortScan: 47, Infiltration: 34, Heartbleed: 1 |
| few-shot | 11% (153/1438) | 443: 341, 1900: 326, 4749: 89, 5351: 80, 5353: 43, 0: 33 | PortScan: 602, Infiltration: 350, Bot: 9, DoS-SlowHTTPTest: 9, Heartbleed: 8 |
| few-shot + 30 lab service flows | 16% (232/1491) | 443: 353, 1900: 349, 4749: 91, 5351: 80, 5353: 44, 13246: 24 | PortScan: 613, Infiltration: 381, Heartbleed: 5, DoS-SlowHTTPTest: 4, Web-XSS: 1 |
| few-shot + 30 local flows | 0% (0/1040) | 443: 339, 1900: 195, 5353: 46, 13246: 30, 4749: 30, 2710: 25 | PortScan: 377, Infiltration: 175, Heartbleed: 8, Bot: 5, Web-BruteForce: 2 |
| few-shot + 30 triaged local flows | 0% (0/661) | 443: 343, 5353: 62, 13246: 30, 4749: 30, 2710: 25, 10004: 20 | PortScan: 42, Infiltration: 13, Heartbleed: 5, Bot: 2 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0% (0/290) | 443: 90, 13246: 30, 2710: 25, 10004: 20, 4749: 15, 50368: 10 | PortScan: 42, Infiltration: 13, Heartbleed: 5, Bot: 2 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0% (0/203) | 443: 87, 2710: 15, 50368: 10, 51972: 10, 55354: 10, 80: 10 | PortScan: 42, Infiltration: 13, Heartbleed: 5, Bot: 2 |
| few-shot + 30 triaged local flows + exemplar envelope | 0% (0/230) | 443: 122, 4749: 15, 50368: 10, 51972: 10, 55354: 10, 80: 10 | PortScan: 42, Infiltration: 13, Heartbleed: 5, Bot: 2 |
| few-shot + 30 triaged local flows + local refit anomaly | 0% (0/205) | 443: 64, 10004: 20, 2710: 20, 13246: 20, 50368: 10, 51972: 10 | PortScan: 42, Infiltration: 13, Heartbleed: 5, Bot: 2 |
| few-shot + 30 uncertain local flows | 5% (67/1276) | 443: 348, 1900: 336, 4749: 62, 5353: 50, 5351: 47, 13246: 30 | PortScan: 519, Infiltration: 203, DoS-SlowHTTPTest: 53, Heartbleed: 3, Bot: 1 |
| few-shot + 30 uncertain local flows + exemplar envelope | 7% (65/934) | 1900: 331, 443: 115, 4749: 49, 5351: 47, 13246: 24, 0: 22 | PortScan: 519, Infiltration: 203, DoS-SlowHTTPTest: 53, Heartbleed: 3, Bot: 1 |
| source only + 30 local flows | 0% (0/1038) | 443: 360, 1900: 203, 5353: 45, 4749: 30, 13246: 30, 2710: 25 | DoS-SlowHTTPTest: 277, Infiltration: 169, PortScan: 118, Heartbleed: 8 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 63.4 min.
