# Benign-envelope audit

Generated on 2026-10-30. 324 flows from 3 sessions, scored by the frozen detector. The envelope is the 0.5th–99.5th percentile of each feature over benchmark benign training flows.

| Group | Flows | Mean features outside the envelope |
|---|---:|---:|
| Anomaly-only alerts | 17 | 17.3 |
| Classifier alerts | 12 | 9.7 |
| No alert | 295 | 1.2 |

## Features that separate anomaly-only alerts from quiet flows

| Feature | Outside envelope: anomaly-only | Outside envelope: quiet |
|---|---:|---:|
| Bwd PSH Flags | 100% | 4% |
| Total Length of Bwd Packet | 94% | 0% |
| PSH Flag Count | 94% | 4% |
| Bwd Packet/Bulk Avg | 94% | 4% |
| Total Bwd packets | 88% | 0% |
| ACK Flag Count | 88% | 3% |
| Total Fwd Packet | 88% | 4% |
| Bwd Header Length | 82% | 2% |
| Bwd Packet Length Mean | 76% | 0% |
| Bwd Segment Size Avg | 76% | 0% |
| Subflow Bwd Bytes | 76% | 0% |
| Packet Length Mean | 76% | 1% |

Unlabelled traffic: alerts are candidate false alerts. Accuracy is not reported (rule 4).
