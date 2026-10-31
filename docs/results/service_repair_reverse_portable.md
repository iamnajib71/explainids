# Service-aware adaptation

Generated on 2026-11-01. Model LGBM; source csecicids2018, target cicids2017. Each adaptation condition adds k oracle-balanced labelled attack flows per class plus 1,000 target benign flows, and optionally benign flows from the fit profile (330 flows). Held-in flows are the untrained remainder of that profile; the held-out profile (330 flows, different service configuration) is never trained on. Detection is class-balanced; service columns are benign false-alert rates with 95% Wilson intervals.

| Training | k | Service flows requested (actually added) | Target detection | Held-in FPR | Held-out FPR |
|---|---|---|---|---|---|
| source only: csecicids2018 |  |  | 0.632 | 37.6% (32.5%-42.9%) | 35.8% (30.8%-41.1%) |
| both environments |  |  | 0.933 | 45.8% (40.5%-51.2%) | 46.1% (40.8%-51.5%) |
| few-shot (no service flows) | 50 | 0 (0) | 0.963 | 39.4% (34.3%-44.8%) | 39.3% (34.0%-44.8%) |
| few-shot (no service flows) + exemplar envelope | 50 | 0 (0) | 0.963 | 39.4% (34.3%-44.8%) | 39.3% (34.0%-44.8%) |
| few-shot + 10 service flows | 50 | 10 (18) | 0.967 | 6.4% (0.0%-37.4%) | 6.1% (0.0%-35.5%) |
| few-shot + 10 triaged flows | 50 | 10 (18) | 0.967 | 0.0% (0.0%-1.2%) | 0.0% (0.0%-1.2%) |
| few-shot + 10 triaged flows + exemplar envelope | 50 | 10 (18) | 0.967 | 0.0% (0.0%-1.2%) | 0.0% (0.0%-1.2%) |
| few-shot + 10 service flows + exemplar envelope | 50 | 10 (18) | 0.967 | 6.4% (0.0%-37.4%) | 6.1% (0.0%-35.5%) |
| few-shot + 30 service flows | 50 | 30 (37) | 0.967 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |
| few-shot + 30 triaged flows | 50 | 30 (37) | 0.964 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |
| few-shot + 30 triaged flows + exemplar envelope | 50 | 30 (37) | 0.959 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |
| few-shot + 30 service flows + exemplar envelope | 50 | 30 (37) | 0.967 | 0.0% (0.0%-1.3%) | 0.0% (0.0%-1.2%) |

Benign flows carry no attack denominator, so detection is not defined for the profile columns. Service flows used for training are excluded from the held-in evaluation. The sampler takes at least one flow from every destination port with two or more flows, so the number actually added can exceed the number requested. Accuracy is not reported (rule 4).

Total run time 42.4 min.
