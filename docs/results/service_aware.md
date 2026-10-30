# Service-aware adaptation

Generated on 2026-10-29. Model LGBM; source cicids2017, target csecicids2018. Each adaptation condition adds k oracle-balanced labelled attack flows per class plus 1,000 target benign flows, and optionally benign flows from the fit profile (330 flows). Held-in flows are the untrained remainder of that profile; the held-out profile (330 flows, different service configuration) is never trained on. Detection is class-balanced; service columns are benign false-alert rates with 95% Wilson intervals.

| Training | k | Service flows requested (actually added) | Target detection | Held-in FPR | Held-out FPR |
|---|---|---|---|---|---|
| source only: cicids2017 |  |  | 0.548 | 18.2% (14.4%-22.7%) | 9.1% (6.4%-12.7%) |
| both environments |  |  | 0.996 | 9.1% (6.4%-12.7%) | 9.1% (6.4%-12.7%) |
| few-shot (no service flows) | 10 | 0 (0) | 0.941 | 12.3% (9.0%-16.4%) | 6.4% (3.5%-10.6%) |
| few-shot + 30 service flows | 10 | 30 (37) | 0.947 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |
| few-shot + 100 service flows | 10 | 100 (102) | 0.948 | 0.0% (0.0%-1.7%) | 0.0% (0.0%-1.2%) |
| few-shot (no service flows) | 50 | 0 (0) | 0.979 | 41.1% (34.3%-48.1%) | 33.6% (25.0%-42.9%) |
| few-shot + 30 service flows | 50 | 30 (37) | 0.982 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |
| few-shot + 100 service flows | 50 | 100 (102) | 0.981 | 0.0% (0.0%-1.7%) | 0.0% (0.0%-1.2%) |

Benign flows carry no attack denominator, so detection is not defined for the profile columns. Service flows used for training are excluded from the held-in evaluation. The sampler takes at least one flow from every destination port with two or more flows, so the number actually added can exceed the number requested. Accuracy is not reported (rule 4).

Total run time 19.8 min.
