# Pre-specified test: how long does an attacker go unnoticed? ("Attack Night")

Written and committed on 7 November 2026, before `scripts/attack_night_eval.py` was first run. False alerts are
usually reported as a rate. An analyst experiences them as a queue, and an attack behind the queue goes
unnoticed. This test turns the earlier results into that measure: minutes of attacker freedom.

## Design

- **Background:** the untouched second evening (1 November; 12 blocks, 4,634 flows). Its blocks are joined end to
  end into one hour of observed traffic (the 10-minute gaps, which were not captured, are removed).
- **Attack campaign:** every flow of one isolated-lab replicate (port scan, SSH and FTP brute force, incomplete
  HTTP probes, SYN burst; about one minute), with its own relative timing, inserted at a random moment. Flows are
  scored independently, so this is what the detector would see had the attack happened on that network; no attack
  traffic is ever sent on it. Replicates B and C are used; replicate A supplies the wrongly dismissed attacks below.
- **Injections:** 20 uniformly random start times per seed and replicate (seeds 42, 1, 2, 3, 4): 200 per condition,
  the same start times for every condition.
- **Detectors** (k = 50 few-shot labels, `--portable` primary, all features secondary; local fit data from the
  first evening only):
  1. *Deployed:* few-shot.
  2. *Repaired:* few-shot + 30 triaged local flows + exemplar envelope.
  3. *Poisoned:* the repair after an analyst wrongly dismissed 3 replicate-A attacks in triage.
  4. *Poisoned, gated:* the same, with dismissals admitted only inside the envelope.
- **Analyst:** works through alerts first in, first out, one alert every s seconds, starting at the beginning of
  the hour and continuing after it until the queue is empty. An alert enters the queue when its flow ends. s = 60
  is primary; 30, 120 and 300 are reported.
- **Measures per injection:** *time to notice* = when the analyst reaches the first attack alert, minus the attack's
  start; *missed* if no attack flow is flagged; *over before noticed* if the campaign's last flow ended before that.

## Hypotheses

- **H1 (primary).** At s = 60, median time to notice is shorter for *Repaired* than for *Deployed*: paired
  Wilcoxon signed-rank test over injections, p < 0.05. Injections share one evening, so the sweep over s and the
  per-seed medians are reported to show it does not hinge on one setting.
- **H2.** *Repaired* misses no more injections than *Deployed* (difference ≤ 2 percentage points).
- **H3.** *Poisoned* misses more of the dismissed attack types (port scan and SYN burst flows) than *Repaired*,
  and *Poisoned, gated* misses no more than *Repaired* + 2 points.

Results: `docs/results/attack_night[_portable].md` and `.json`; the console's Attack Night view reads only the
aggregated per-10-second alert counts of one representative injection (the median case), no flows or addresses.
Anything else is labelled exploratory, and every outcome is reported as it falls.
