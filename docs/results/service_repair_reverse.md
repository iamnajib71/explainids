# Service-aware adaptation

Generated on 2026-10-31. Model LGBM; source csecicids2018, target cicids2017. Each adaptation condition adds k oracle-balanced labelled attack flows per class plus 1,000 target benign flows, and optionally benign flows from the fit profile (330 flows). Held-in flows are the untrained remainder of that profile; the held-out profile (330 flows, different service configuration) is never trained on. Detection is class-balanced; service columns are benign false-alert rates with 95% Wilson intervals.

| Training | k | Service flows requested (actually added) | Target detection | Held-in FPR | Held-out FPR |
|---|---|---|---|---|---|
| source only: csecicids2018 |  |  | 0.630 | 18.2% (14.4%-22.7%) | 64.8% (59.6%-69.8%) |
| both environments |  |  | 0.942 | 9.1% (6.4%-12.7%) | 39.4% (34.3%-44.8%) |
| few-shot (no service flows) | 50 | 0 (0) | 0.987 | 32.1% (25.6%-44.8%) | 62.7% (55.2%-74.4%) |
| few-shot (no service flows) + exemplar envelope | 50 | 0 (0) | 0.987 | 32.1% (25.6%-44.8%) | 62.7% (55.2%-74.4%) |
| few-shot + 10 service flows | 50 | 10 (18) | 0.988 | 30.0% (20.2%-37.4%) | 31.0% (21.6%-43.2%) |
| few-shot + 10 triaged flows | 50 | 10 (18) | 0.988 | 27.3% (21.7%-36.8%) | 43.6% (25.6%-65.7%) |
| few-shot + 10 triaged flows + exemplar envelope | 50 | 10 (18) | 0.988 | 0.0% (0.0%-1.2%) | 19.3% (0.0%-65.7%) |
| few-shot + 10 service flows + exemplar envelope | 50 | 10 (18) | 0.988 | 6.4% (0.0%-37.4%) | 7.8% (0.0%-43.2%) |
| few-shot + 30 service flows | 50 | 30 (37) | 0.988 | 31.3% (25.1%-38.0%) | 36.5% (25.6%-65.7%) |
| few-shot + 30 triaged flows | 50 | 30 (37) | 0.988 | 23.5% (17.2%-37.3%) | 48.7% (25.6%-65.7%) |
| few-shot + 30 triaged flows + exemplar envelope | 50 | 30 (37) | 0.988 | 0.0% (0.0%-1.3%) | 18.5% (0.0%-35.8%) |
| few-shot + 30 service flows + exemplar envelope | 50 | 30 (37) | 0.988 | 0.0% (0.0%-1.3%) | 6.2% (0.0%-35.5%) |

Benign flows carry no attack denominator, so detection is not defined for the profile columns. Service flows used for training are excluded from the held-in evaluation. The sampler takes at least one flow from every destination port with two or more flows, so the number actually added can exceed the number requested. Accuracy is not reported (rule 4).

Total run time 36.7 min.
