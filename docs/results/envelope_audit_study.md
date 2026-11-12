# Benign-envelope audit

Generated on 2026-10-31. 3,307 flows from 12 sessions, scored by the frozen detector. The envelope is the 0.5th–99.5th percentile of each feature over benchmark benign training flows.

| Group | Flows | Mean features outside the envelope |
|---|---:|---:|
| Anomaly-only alerts | 103 | 11.5 |
| Classifier alerts | 87 | 8.1 |
| No alert | 3117 | 2.0 |

## Features that separate anomaly-only alerts from quiet flows

| Feature | Outside envelope: anomaly-only | Outside envelope: quiet |
|---|---:|---:|
| Fwd Act Data Pkts | 48% | 5% |
| Packet Length Max | 48% | 7% |
| Bwd Packet Length Max | 47% | 7% |
| Packet Length Std | 46% | 7% |
| Packet Length Variance | 46% | 7% |
| Bwd Packet Length Std | 45% | 8% |
| Fwd Bytes/Bulk Avg | 40% | 5% |
| Total Length of Fwd Packet | 35% | 1% |
| Total Bwd packets | 34% | 0% |
| Active Max | 36% | 3% |
| Total Length of Bwd Packet | 33% | 1% |
| Packet Length Mean | 38% | 6% |

Unlabelled traffic: alerts are candidate false alerts. Accuracy is not reported (rule 4).
