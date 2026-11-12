# Pre-specified confirmations: dismissal gate, unseen-attack cost, refit cadence

Written and committed on 4 November 2026, before any of the runs below. Two results in `docs/RESEARCH.md` rest on
thin evidence: the dismissal gate (exploratory, added after a smoke run) and the unseen-attack cost of the local veto
(one seed). A third question, how long a site's model of normal stays valid, has not been tested. Each is fixed here
so the outcome cannot be tuned to the data. Whatever the outcome, it is reported in `docs/RESEARCH.md` and the
thesis evidence chain (E10, E11) is updated or downgraded.

## C1. The dismissal gate on fresh dismissals

- **Data.** Wrongly dismissed attacks come from lab replicate `run_20261025T050628Z` (B), not A as in the exploratory
  run; recall is measured on replicates A and C. Seeds 5, 6, 7, 8, 9 (new) draw the labels, triage sets and
  dismissed flows. Local normal traffic: the 30 October evening. Script: `scripts/gate_confirm.py`.
- **Rule, per dismissal count k = 3 and k = 10.** Confirmed if (a) the gated model's recall on held-out lab attacks
  is within 2 points of the clean model's in at least 4 of 5 seeds, and (b) the gate keeps at least 90% of the
  legitimate triaged flows; and, at k = 3, (c) the ungated model's mean recall is at least 10 points below clean
  (the poisoning effect replicates). Primary: without port and TCP-window features (`--portable`); all features
  reported as secondary.

## C2. The unseen-attack cost, over five seeds

- **Data.** `scripts/unseen_veto_eval.py` as committed, with `--seed` 1, 2, 3, 4 added to the existing seed 42.
  The seed draws the few-shot labels and the triage set; the classifier's own random state is fixed.
- **Rule.** The cost is *confirmed* if, pooled over the five seeds, the exemplar envelope removes more than 10% of
  the unseen-attack flows that only the anomaly layer catches. *Exemplar pays less* is confirmed if its removed
  share is below the local threshold's in at least 4 of 5 seeds. Primary: `--portable`; all features secondary.

## C3. Refit cadence

- **Data.** The repair (30 triaged flows plus exemplar envelope) is fitted on local traffic of two ages and scored
  on the 1 November evening: the 29 October WiFi pilot (two sessions, 222 flows, three days old) and the
  30 October evening (3,307 flows, two days old), also subsampled to 222 flows in three draws per seed so that age
  is compared at equal size. Seeds 42, 1, 2, 3, 4. Script: `scripts/cadence_eval.py`, `--portable`.
- **Rule.** Decay is detected if the three-day-old pool's per-block alert rates (seed-averaged) exceed those of the
  equal-size two-day-old pool with a two-sided sign test p < 0.05. Otherwise "no decay detected at this age
  difference" is reported; a one-day difference is a weak test and is described as such.
