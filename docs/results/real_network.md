# Real-network evaluation

Generated on 2026-10-31. Model LGBM; source cicids2017, target csecicids2018, k = 50 labelled target flows per attack class. Evaluated on 3,307 flows in 12 capture blocks (0.93 h of observed traffic) from a network in ordinary use. Local training flows come only from 2 sessions recorded on an earlier day (222 flows). No attack traffic was generated, so alerts are counted as false alerts (an upper bound: the traffic is unlabelled). Intervals are a 95% bootstrap over blocks; seed-dependent conditions show the mean and range over 5 seeds.

| Training | Target detection | Real-network alert rate | 95% interval (blocks) | Alerts per hour |
|---|---|---|---|---|
| source only | 0.548 | 5.7% | 3.8%–8.0% | 204 |
| source only + local anomaly threshold | 0.546 | 3.2% | 1.4%–5.4% | 112 |
| source only + two-envelope anomaly | 0.548 | 4.8% | 2.8%–7.2% | 169 |
| source only + exemplar envelope | 0.546 | 2.8% | 1.1%–5.0% | 101 |
| both environments | 0.996 | 5.8% | 3.6%–8.0% | 207 |
| few-shot | 0.980 | 7.2% (seeds 6.4%–8.9%) | 4.0%–11.5% | 254 |
| few-shot + 30 lab service flows | 0.982 | 7.5% (seeds 6.3%–10.1%) | 3.8%–12.8% | 266 |
| few-shot + 30 local flows | 0.982 | 5.1% (seeds 4.8%–5.3%) | 2.8%–8.2% | 182 |
| few-shot + 30 triaged local flows | 0.981 | 4.9% (seeds 4.4%–5.2%) | 3.2%–6.6% | 172 |
| few-shot + 30 triaged local flows + local anomaly threshold | 0.980 | 2.2% (seeds 2.0%–2.5%) | 1.2%–3.8% | 77 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 0.981 | 4.0% (seeds 3.7%–4.3%) | 2.7%–5.8% | 143 |
| few-shot + 30 triaged local flows + exemplar envelope | 0.980 | 1.9% (seeds 1.5%–2.0%) | 1.0%–3.3% | 66 |
| source only + 30 local flows | 0.555 | 3.9% (seeds 3.5%–4.2%) | 2.6%–5.3% | 137 |

## Where the alerts fall

A service (destination port, at least 5 flows) is *collapsed* when at least 80% of its flows alert. The share of alerts inside collapsed services measures how service-shaped the failure is.

| Training | Alerts in collapsed services | Alerts by destination port (pooled over seeds) | Predicted classes |
|---|---|---|---|
| source only | 0% (0/190) | 443: 85, 1900: 11, 5351: 10, 5353: 8, 5161: 5, 63492: 5 | PortScan: 48, Infiltration: 25, DoS-SlowHTTPTest: 11, Bot: 3 |
| source only + local anomaly threshold | 0% (0/105) | 443: 17, 1900: 11, 5351: 10, 5161: 5, 55490: 4, 57449: 4 | PortScan: 48, Infiltration: 25, DoS-SlowHTTPTest: 11, Bot: 3 |
| source only + two-envelope anomaly | 0% (0/158) | 443: 59, 1900: 11, 5351: 10, 5161: 5, 5353: 5, 55490: 4 | PortScan: 48, Infiltration: 25, DoS-SlowHTTPTest: 11, Bot: 3 |
| source only + exemplar envelope | 0% (0/94) | 1900: 11, 5351: 10, 5161: 5, 443: 5, 55490: 4, 57449: 4 | PortScan: 48, Infiltration: 25, DoS-SlowHTTPTest: 11, Bot: 3 |
| both environments | 12% (24/193) | 443: 100, 5351: 24, 9199: 11, 5353: 7, 63492: 4, 9026: 4 | PortScan: 49, Infiltration: 30 |
| few-shot | 17% (207/1187) | 443: 394, 5351: 120, 9199: 69, 1900: 55, 5353: 40, 5161: 27 | PortScan: 364, Infiltration: 326, Bot: 11, Heartbleed: 3, DoS-SlowHTTPTest: 1 |
| few-shot + 30 lab service flows | 25% (311/1243) | 443: 392, 5351: 120, 9199: 68, 1900: 67, 5353: 38, 5161: 23 | PortScan: 384, Infiltration: 370, DoS-SlowHTTPTest: 1 |
| few-shot + 30 local flows | 5% (42/850) | 443: 401, 5351: 90, 5353: 46, 9199: 28, 63492: 19, 0: 18 | PortScan: 196, Infiltration: 118, Heartbleed: 4, DoS-SlowHTTPTest: 1 |
| few-shot + 30 triaged local flows | 9% (76/803) | 443: 399, 5351: 84, 9199: 54, 5353: 48, 63492: 23, 9026: 20 | Infiltration: 151, PortScan: 114, Bot: 3, Heartbleed: 1, DoS-SlowHTTPTest: 1 |
| few-shot + 30 triaged local flows + local anomaly threshold | 21% (76/360) | 5351: 84, 443: 55, 9199: 54, 9026: 20, 6239: 15, 0: 12 | Infiltration: 151, PortScan: 114, Bot: 3, Heartbleed: 1, DoS-SlowHTTPTest: 1 |
| few-shot + 30 triaged local flows + two-envelope anomaly | 11% (76/669) | 443: 296, 5351: 84, 9199: 54, 5353: 33, 9026: 20, 63492: 18 | Infiltration: 151, PortScan: 114, Bot: 3, Heartbleed: 1, DoS-SlowHTTPTest: 1 |
| few-shot + 30 triaged local flows + exemplar envelope | 25% (76/307) | 5351: 84, 9199: 54, 443: 27, 0: 12, 5353: 10, 5906: 8 | Infiltration: 151, PortScan: 114, Bot: 3, Heartbleed: 1, DoS-SlowHTTPTest: 1 |
| source only + 30 local flows | 0% (0/640) | 443: 412, 5353: 40, 63492: 25, 9026: 20, 12178: 11, 58754: 9 | Infiltration: 74, DoS-SlowHTTPTest: 30, PortScan: 19 |

Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.

Total run time 73.6 min.
