# Pre-specified test: a third evening, nine days on (same network)

Written and committed on 7 November 2026 at about 22:55 local time, before the first block of either evening below
was captured. This is **not** an independent network (that test is `PREREGISTRATION_NET2.md`); it is the same home
network, used for two questions the earlier evenings could not answer: does the result hold on an untouched evening
more than a week later, and how quickly does a site's model of normal go stale? The earlier ageing test compared
pools only one day apart (C3, "a weak test").

## Data

- **Evening A:** Saturday 7 November 2026, from about 23:00 local; 12 blocks, the same bounds as before (at most
  5 minutes or 90 MB, 10 minutes apart), `scripts/capture_blocks.py`, study record
  `data/sensor/study_wifi_20261107.json`. Used **only** as a fresh local fit pool.
- **Evening B:** Sunday 8 November 2026, at a time of the team's choosing, identical bounds, study record
  `data/sensor/study_wifi_20261108.json`. Evaluated only; nothing from it is trained on.
- **Old fit pool:** the 30 October sessions (`data/study_sessions.txt`), nine days before evening B.
- Household agreement to passive capture covers these evenings; no traffic is generated.
- Block validity as in the second-network amendment: a block counts if capture exits cleanly and at least 20 flows
  validate; fewer than 6 valid evaluation blocks makes a hypothesis untestable, not failed.

## Hypotheses

- **H1 (replication, primary).** On evening B, with the old (30 October) fit pool, k = 50 and `--portable`,
  *few-shot + 30 triaged local flows + exemplar envelope* has a lower alert rate than *few-shot* in more blocks than
  not: two-sided sign test over blocks on rates averaged over seeds 42, 1, 2, 3, 4; confirmed if p < 0.05 and lower.
- **H2 (detection guard).** Mean benchmark class-balanced detection of that condition is at most 0.01 below
  few-shot's.
- **H3 (ageing, primary).** On evening B, the repair fitted on the nine-day-old pool has higher per-block alert
  rates than the repair fitted on evening A (one day old), with both pools subsampled to the smaller pool's size,
  three draws each per seed: two-sided sign test over blocks on seed- and draw-averaged rates. **Decay is detected
  if p < 0.05 and the old pool is higher**; otherwise "no decay detected at nine days" is reported, with the mean
  difference and its block-bootstrap interval.
- **H4 (secondary).** H1–H3 with all 83 features.

## Analysis

H1, H2: `scripts/real_network_eval.py` as committed, `--fit-sessions` the 30 October sessions, `--study` evening B,
with and without `--portable`; results `docs/results/real_network_day3[_portable].md`.
H3: `scripts/cadence_eval.py` with `--old` the 30 October sessions, `--recent` evening A, `--study` evening B and
the equal-size option committed with this file; results `docs/results/cadence_day3[_portable].md`.
No setting changes after evening B is seen; anything else is labelled exploratory. Whatever the outcome, it is
reported in `docs/RESEARCH.md`, and E9 and the refit-cadence statement in `docs/THESIS.md` are updated.
