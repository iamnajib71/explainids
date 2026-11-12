# Pre-specified replication: a second, independent network

Written and committed on 7 November 2026, before any traffic on the second network has been captured. Every
real-network result so far (E7–E9) comes from one home WiFi network; this is the study's main threat to validity.
The replication below uses the recipe and analysis exactly as committed, on a network that shares no devices,
router or household with the first, so the outcome cannot be tuned to it.

## Network and consent

- A different household's home network in ordinary use, captured by a team member who lives there, with everyone in
  the household agreeing verbally before the first capture. No traffic is generated; no attack is run on it.
- Capture on that member's Windows PC with `scripts/capture_pcap_blocks.ps1` (Wireshark only): non-promiscuous, full
  packets, 12 blocks of at most 5 minutes or 90 MB, 10 minutes apart, the same bounds as the first network.
- The block folder is brought to the analysis PC in person and imported with
  `scripts/import_pcap_blocks.py --discard-pcap`: raw packets are deleted once their flows validate, only flow
  features are kept, addresses are pseudonymised in anything shared, and only aggregates are published.

## Data

- **Primary design (two evenings).** Evening A is the only source of local fit flows; evening B (a later day) is
  evaluated. Every validated block of evening B is used; a block that fails capture or validation is reported and
  excluded as a whole, never for its result.
- **Fallback, fixed now (one evening only).** If only one evening can be captured, its first 6 blocks are the fit
  data and its last 6 are evaluated. With 6 blocks the smallest attainable two-sided sign-test p is 0.031, so the
  fallback can still confirm H1, but only if every block agrees; this is reported as a weaker test.
- **Benchmark:** the corrected CIC-IDS2017 → CSE-CIC-IDS2018 pair, as before. Nothing from the first network is used.

## Hypotheses (identical to `PREREGISTRATION_DAY2.md`)

- **H1 (primary).** With k = 50 labelled target attacks per class and `--portable` features, *few-shot + 30
  triaged local flows + exemplar envelope* has a lower alert rate than *few-shot* in more blocks than not. Two-sided
  sign test over blocks on per-block alert rates averaged over seeds 42, 1, 2, 3, 4; ties dropped. **Confirmed if
  p < 0.05 and the direction is lower.**
- **H2 (detection guard).** Mean benchmark class-balanced detection of that condition is no more than 0.01 below
  few-shot's (mean over the five seeds ≥ −0.01).
- **H3 (secondary).** H1 and H2 with all 83 features (no `--portable`).
- **H4 (secondary).** *Few-shot + 30 lab service flows* does not lower the alert rate (sign test p ≥ 0.05, or
  higher). Reported either way.

## Analysis

`scripts/real_network_eval.py` exactly as committed with this file, run with `--fit-sessions` set to evening A's
sessions (or the first 6 blocks) and `--study` to evening B's study record (or one listing the last 6 blocks), once
with `--portable` and once without; results in `docs/results/real_network_net2_portable.md` and
`docs/results/real_network_net2.md`. No setting changes after results are seen; anything else is exploratory.

## Reporting

Whatever the outcome, H1–H4 are reported with p-values and effect sizes in `docs/RESEARCH.md`, and E9 in
`docs/THESIS.md` becomes "replicated on two networks", "replicated in part" or "not replicated" accordingly.

## Amendment, 7 November 2026 (before any capture on the second network)

Added to make the outcome precise and comparable with the first network; nothing about the second network has
been observed. The capture and import path was checked end to end on the first network's PC (two 30-second
blocks, discarded afterwards).

- **Validity of a block.** A block counts if its capture exits cleanly and at least 20 flows validate; otherwise it
  is excluded as a whole and reported. If fewer than 6 evaluation blocks remain, H1 is reported as untestable,
  not as failed.
- **Independence check, recorded before analysis.** Different household, router and internet connection from the
  first network; no device of the first household on it during capture. Recorded as yes/no in the study notes.
- **Effect size.** Alongside each sign test: the pooled alert rate of each condition with its 95% block-bootstrap
  interval (as `real_network_eval.py` already computes), alerts per hour, and the relative reduction of H1's
  condition against few-shot. Replication is judged on H1's direction and p only; the size is reported, not tested.
- **Exploratory, labelled as such (E1).** Does a repair fitted on the *first* network help the second? The
  first network's triaged flows and envelope are applied to the second network's evaluation blocks. If the repair
  is site-specific, as the thesis argues, this should do less than the second network's own repair.
- **Exploratory (E2).** Composition of the remaining alerts by destination port class and by classifier versus
  anomaly layer, as for the first network, to see whether the same mechanisms drive them.

## Status, 12 November 2026

Not run. No second household was available for capture before the project deadline, so no data exist for this test and none of its hypotheses is confirmed or refuted. The study's evidence comes from one home network on three evenings; this is reported as its main limitation.
