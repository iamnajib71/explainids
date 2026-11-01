# Benign-envelope audit

Generated on 2026-11-02. 4,634 flows from 12 sessions, scored by the frozen detector. The envelope is the 0.5th–99.5th percentile of each feature over benchmark benign training flows.

| Group | Flows | Mean features outside the envelope |
|---|---:|---:|
| Anomaly-only alerts | 89 | 12.5 |
| Classifier alerts | 147 | 8.6 |
| No alert | 4398 | 1.6 |

## Features that separate anomaly-only alerts from quiet flows

| Feature | Outside envelope: anomaly-only | Outside envelope: quiet |
|---|---:|---:|
| Bwd PSH Flags | 51% | 1% |
| Fwd Act Data Pkts | 52% | 3% |
| Total Bwd packets | 45% | 0% |
| Bwd Header Length | 43% | 1% |
| Down/Up Ratio | 48% | 7% |
| Active Max | 45% | 4% |
| PSH Flag Count | 42% | 1% |
| Total Length of Fwd Packet | 38% | 0% |
| ACK Flag Count | 37% | 0% |
| Packet Length Max | 42% | 5% |
| Bwd Packet Length Max | 42% | 5% |
| Fwd Bytes/Bulk Avg | 39% | 3% |

Unlabelled traffic: alerts are candidate false alerts. Accuracy is not reported (rule 4).
