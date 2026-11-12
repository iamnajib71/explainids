# Real-network evaluation

Generated on 2026-11-09. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 4,117 flows in 12 capture blocks (0.99 h of observed traffic) from a network in ordinary use. Local training flows come only from 12 sessions recorded on an earlier day (3307 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.548 | 3.4% | 2.3%–4.2% | 143 |
| source only + local anomaly threshold | 0.546 | 2.0% | 1.2%–2.5% | 83 |
| source only + two-envelope anomaly | 0.546 | 2.0% | 1.4%–2.4% | 82 |
| source only + exemplar envelope | 0.548 | 1.8% | 1.2%–2.2% | 75 |
| source only + local refit anomaly | 0.546 | 1.8% | 1.2%–2.3% | 77 |
| both environments | 0.996 | 2.8% | 1.5%–3.8% | 117 |
| few-shot | 0.980 | 5.1% (seeds 4.4%–6.5%) | 3.3%–7.3% | 214 |
| few-shot + 30 lab service flows | 0.982 | 5.5% (seeds 4.3%–7.5%) | 3.3%–8.2% | 229 |
| few-shot + 30 local flows | 0.981 | 3.4% (seeds 3.0%–3.8%) | 1.7%–4.7% | 143 |
| few-shot + 30 triaged local flows | 0.981 | 2.4% (seeds 2.2%–2.8%) | 1.2%–3.6% | 102 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.980 | 0.8% (seeds 0.6%–1.0%) | 0.2%–1.4% | 32 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.980 | 0.6% (seeds 0.5%–0.9%) | 0.2%–1.1% | 24 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.981 | 0.5% (seeds 0.3%–0.8%) | 0.2%–1.1% | 21 |
| few-shot + 30 triaged local flows + local refit anomaly | 0.980 | 0.5% (seeds 0.3%–0.8%) | 0.1%–1.0% | 21 |
| few-shot + 30 uncertain local flows | 0.980 | 4.0% (seeds 3.0%–4.8%) | 2.2%–5.5% | 166 |
| few-shot + 30 uncertain local flows + exemplar envelope | 0.980 | 2.3% (seeds 1.3%–3.2%) | 1.1%–3.7% | 97 |
| source only + 30 local flows | 0.555 | 2.9% (seeds 2.7%–3.1%) | 1.5%–3.9% | 119 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/142) | 443: 61, 1900: 12, 9683: 8, 5972: 5, 4649: 4, 13184: 4 | Infiltration: 34, DoS-SlowHTTPTest: 23, PortScan: 9, DoS-GoldenEye: 4, Bot: 2 |
| source only + local anomaly threshold | 0% (0/82) | 1900: 12, 443: 9, 9683: 8, 5972: 5, 4649: 4, 13184: 4 | Infiltration: 34, DoS-SlowHTTPTest: 23, PortScan: 9, DoS-GoldenEye: 4, Bot: 2 |
| source only + two-envelope anomaly | 0% (0/81) | 1900: 12, 443: 9, 9683: 8, 5972: 5, 4649: 4, 13184: 4 | Infiltration: 34, DoS-SlowHTTPTest: 23, PortScan: 9, DoS-GoldenEye: 4, Bot: 2 |
| source only + exemplar envelope | 0% (0/74) | 1900: 12, 9683: 8, 5972: 5, 4649: 4, 13184: 4, 13259: 3 | Infiltration: 34, DoS-SlowHTTPTest: 23, PortScan: 9, DoS-GoldenEye: 4, Bot: 2 |
| source only + local refit anomaly | 0% (0/76) | 1900: 12, 9683: 8, 5972: 5, 4649: 4, 13184: 4, 13259: 3 | Infiltration: 34, DoS-SlowHTTPTest: 23, PortScan: 9, DoS-GoldenEye: 4, Bot: 2 |
| both environments | 0% (0/116) | 443: 69, 55026: 3, 3516: 3, 5972: 3, 8045: 3, 2122: 3 | Infiltration: 33, PortScan: 6, Bot: 2 |
| few-shot | 17% (184/1058) | 443: 283, 3516: 120, 1900: 70, 9683: 52, 13184: 44, 5972: 37 | Infiltration: 607, PortScan: 111, DoS-SlowHTTPTest: 10, Bot: 7, Heartbleed: 1 |
| few-shot + 30 lab service flows | 25% (279/1134) | 443: 290, 3516: 120, 1900: 95, 9683: 59, 13184: 49, 5972: 36 | Infiltration: 647, PortScan: 134, DoS-SlowHTTPTest: 4, Bot: 3 |
| few-shot + 30 local flows | 6% (40/707) | 443: 283, 9683: 42, 13184: 36, 1900: 28, 5972: 28, 4649: 26 | Infiltration: 300, PortScan: 62, Bot: 8, DoS-SlowHTTPTest: 5 |
| few-shot + 30 triaged local flows | 0% (0/504) | 443: 280, 5353: 41, 8045: 15, 2122: 12, 64063: 12, 5972: 10 | Infiltration: 54, PortScan: 16, DoS-SlowHTTPTest: 4, Bot: 2 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0% (0/157) | 443: 42, 55026: 13, 13259: 10, 4652: 10, 5968: 8, 2122: 6 | Infiltration: 54, PortScan: 16, DoS-SlowHTTPTest: 4, Bot: 2 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0% (0/121) | 443: 48, 55026: 13, 13259: 10, 5972: 8, 9683: 7, 13178: 5 | Infiltration: 54, PortScan: 16, DoS-SlowHTTPTest: 4, Bot: 2 |
| few-shot + 30 triaged local flows + exemplar envelope | 0% (0/104) | 443: 18, 55026: 13, 13259: 10, 5972: 7, 4649: 7, 9683: 7 | Infiltration: 54, PortScan: 16, DoS-SlowHTTPTest: 4, Bot: 2 |
| few-shot + 30 triaged local flows + local refit anomaly | 0% (0/104) | 443: 23, 55026: 13, 13259: 10, 5972: 7, 9683: 7, 64827: 4 | Infiltration: 54, PortScan: 16, DoS-SlowHTTPTest: 4, Bot: 2 |
| few-shot + 30 uncertain local flows | 7% (59/821) | 443: 287, 1900: 81, 3516: 57, 13184: 33, 9683: 31, 5972: 29 | Infiltration: 341, PortScan: 114, DoS-SlowHTTPTest: 5, Bot: 1 |
| few-shot + 30 uncertain local flows + exemplar envelope | 12% (59/480) | 1900: 81, 3516: 59, 13184: 33, 9683: 31, 5972: 27, 13178: 24 | Infiltration: 341, PortScan: 114, DoS-SlowHTTPTest: 5, Bot: 1 |
| source only + 30 local flows | 0% (0/588) | 443: 304, 9683: 28, 5972: 19, 13259: 15, 4649: 15, 5353: 15 | Infiltration: 155, PortScan: 32, DoS-GoldenEye: 20, DoS-SlowHTTPTest: 19, Bot: 4 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 65.9 min.
