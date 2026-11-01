# Pre-specified confirmation: second real-network evening

Written and committed on 1 November 2026, while the second evening's capture was still running and before any
of its flows were scored. The recipe below was chosen on the first evening (30 October), which has been examined;
the team decision of 28 October requires a candidate chosen on examined data to be confirmed on untouched data.
This file fixes the hypothesis, data, analysis and decision rule in advance so the confirmation cannot be tuned
to its result.

## Data

- **Evaluation:** the 12 blocks in `data/sensor/study_wifi_20261101.json` (home WiFi, Sunday 1 November 2026
  from 22:02 local, same capture bounds as day 1). Every validated block is used; no block is dropped for its
  result. If a block fails capture or validation, it is reported and excluded as a whole.
- **Local fit data:** only the 12 day-1 sessions (`data/study_sessions.txt`). Nothing from day 2 is trained on.
- **Benchmark:** the corrected CIC-IDS2017 → CSE-CIC-IDS2018 pair, as on day 1.

## Hypotheses

- **H1 (primary).** With k = 50 labelled target attacks per class and the shortcut-free feature set
  (`--portable`), *few-shot + 30 triaged local flows + exemplar envelope* has a lower alert rate than *few-shot*
  in more blocks than not. Test: two-sided sign test over blocks on per-block alert rates averaged over the five
  seeds (42, 1, 2, 3, 4); ties dropped. **Confirmed if p < 0.05 and the direction is lower.**
- **H2 (detection guard).** Mean benchmark class-balanced detection of that condition is no more than 0.01 below
  few-shot's. **Confirmed if the mean difference over the five seeds is ≥ −0.01.**
- **H3 (secondary).** The same two comparisons with all 83 features (no `--portable`).
- **H4 (secondary).** *Few-shot + 30 lab service flows* does not lower the alert rate (sign test p ≥ 0.05, or
  higher). Reported either way.

## Analysis

`scripts/real_network_eval.py` exactly as committed at the time of this file (conditions, 30 local flows,
1% envelope budget, five seeds), once with `--portable` and once without, with results in
`docs/results/real_network_day2_portable.md` and `docs/results/real_network_day2.md`. No setting is changed
after day-2 results are seen; any additional analysis is labelled exploratory.

## Reporting

Whatever the outcome, H1–H4 are reported with their p-values and effect sizes in `docs/RESEARCH.md`. A failure
to confirm is reported as such and E9 in `docs/THESIS.md` is downgraded accordingly.
