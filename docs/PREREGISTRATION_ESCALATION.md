# Pre-specified test: can repetition recover what the local veto hides?

Written and committed on 11 November 2026, before the script below was run on any attack class.

## The problem being solved

The local model of normal (exemplar envelope) removes anomaly alerts that resemble what the site always does. Its
measured price (C2, `docs/RESEARCH.md`) is 29.3% of the unseen-attack flows that only the anomaly layer catches
(13.6% with all features), almost all DoS-Slowloris: each slow connection looks like one of the site's idle HTTPS
sessions. The console already keeps vetoed alerts as low priority instead of deleting them. This test asks whether
that low-priority log can pay the price back.

**Idea.** One quiet connection resembles normal traffic; many quiet connections to the same service in a minute do
not resemble anything the site has done. An attack that hides inside the envelope flow by flow may still stand out
by repetition.

## The rule (fixed here)

- A flow is **demoted** when the benchmark anomaly layer flags it, the classifier calls it benign, and the exemplar
  envelope vetoes it.
- A demoted flow is **escalated** back to an alert when at least **N** demoted flows (itself included) share its
  destination address and destination port and started within the **60 seconds** ending at its start.
- **N is set from the site's own earlier traffic only, with no attack labels:** N = 1 + the largest such count seen
  anywhere on the earlier evening (30 October), and never below 3. In words: more repetition than this site has
  ever shown.
- Nothing is tuned on attack data or on the evaluation evenings. The window (60 s) and the floor (3) are fixed here.

## Data and design

- Unseen attacks: the leave-one-class-out design of `scripts/unseen_veto_eval.py`, unchanged (each attack class
  removed from all training in turn; k = 50; 30 triaged local flows; exemplar envelope fitted on 30 October), on the
  CIC-IDS2017 and CSE-CIC-IDS2018 test splits, seeds 42, 1, 2, 3, 4. Destination address, port and start time come
  from the benchmark's own flow records.
- Price: the pre-registered evenings of 1 November and 8 November (12 blocks each), scored by the same
  leave-one-out models. Repetition is counted within a capture block.

## Hypotheses

- **H1 (recovery, primary).** Without port and TCP-window features, pooled over classes, both test splits and five
  seeds, the share of anomaly-only unseen detections still lost after escalation is **at most 10%**: the same rule
  the veto failed at 29.3%. Reported with the per-class counts and the per-seed shares.
- **H2 (price, primary).** On each of the two evenings, escalation raises the real-network alert rate by **no more
  than 0.2 percentage points** (mean over leave-one-out models and seeds), reported with the count of escalated
  alerts per hour.
- **H3 (secondary).** H1 and H2 with all 83 features.

The fix is **confirmed** only if H1 and H2 both hold. If H1 holds and H2 fails, the rule recovers attacks at a price
that is reported. If H1 fails, the slow-attack cost stands as a limit of the repair.

## Not tested here

SSH brute force passing the dismissal gate (E10) is a different mechanism: the retrained classifier calls it benign,
and the rule above only sees flows the anomaly layer flags. Whether any of those flows are demoted and escalated is
reported as **exploratory**, with no hypothesis.

## Analysis

`scripts/escalation_eval.py` (committed with this file), with and without `--portable`; results
`docs/results/escalation[_portable].md` and `.json`. No setting changes after the first run on an attack class;
anything else is labelled exploratory. Whatever the outcome, it is reported in `docs/RESEARCH.md` and E11 in
`docs/THESIS.md` is updated.
