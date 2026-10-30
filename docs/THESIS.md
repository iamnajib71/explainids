# Thesis path

**Working title.** *Where benchmark intrusion detectors break on a real network, and the cheapest evidence that repairs them.*

## The problem nobody measures

Flow-based ML intrusion detectors report about 99% on CIC-IDS2017 and similar benchmarks. A site that deploys one
does not have that benchmark: it has its own services, its own traffic volumes, its own sensor position and almost no
labelled attacks. The literature mostly answers "does accuracy drop on another dataset?" (it does). It rarely asks the
questions an operator faces on day one:

1. **Which** legitimate traffic will the detector alarm on, and why?
2. What is the **smallest, cheapest local evidence** that fixes that without losing detection?
3. Does the fix, measured on a benchmark, **hold on a real network** in ordinary use?

## Thesis statement

> A benchmark-trained detector's false alarms on a new network are not diffuse noise. They come from a small number of
> identifiable mechanisms: whole-service misclassification by the classifier, an anomaly envelope that today's normal
> traffic exceeds, and sensor-position artefacts that change attack labels. Each mechanism can be diagnosed from
> unlabelled local traffic, and each has a label-cheap repair whose cost on attack detection can be measured.
> The common shortcut, a few labelled local attacks, restores detection but amplifies the first mechanism, so it is
> unsafe on its own.

## Evidence chain

Each link is a script in this repository with a committed result file. Status reflects what is measured today.

| # | Claim | Evidence | Status |
|---|---|---|---|
| E1 | Benchmark scores do not transfer between networks | 2017 → 2018 catches 8.2% of attacks; 2018 → 2017 70.3% ([cross_dataset](results/cross_dataset.md)) | Measured |
| E2 | Local benign traffic restores the false-alarm budget but not detection | 1,000 local flows: FPR 3.4% → 1.2%, detection 0.55 → 0.32 ([local_calibration](results/local_calibration.md)) | Measured |
| E3 | A few labelled local attacks restore detection but break legitimate services | k = 50: detection 0.98, service false alerts 26–70%; matched target-only control 100% ([multi_env_matched](results/multi_env_matched.md)) | Measured |
| E4 | The breakage is whole-service: a port is flagged entirely or not at all | Port 22 → SSH-BruteForce, FTP data → PortScan, half of port 80 after adaptation ([service_aware](results/service_aware.md)) | Measured, lab services |
| E5 | ~30 benign service flows repair it at no detection cost, and transfer to an unseen configuration | 41.1% → 0/293, held-out 33.6% → 0/330, detection 0.979 → 0.982 ([service_aware](results/service_aware.md)) | Measured, 2 seeds; 10-seed and dose–response replication running |
| E6 | The result holds in the reverse direction | 2018 → 2017 replication ([service_aware_reverse](results/service_aware_reverse.md)) | Running |
| E7 | On a real network, the dominant false-alarm source shifts to the anomaly layer | Live WiFi: 12 of 18 alerts anomaly-only; each lies outside the benchmark benign range on 11–20 volume features, against ~1 for quiet flows | Measured, 3 short captures |
| E8 | Sensor position changes attack labels, not alert volume | Undoing segmentation offload: classifier alerts 6 → 1, total alerts 18 → 18, 14 of 16 paired alerts persist ([offload_counterfactual](results/offload_counterfactual.md)) | Measured, 1 capture; extending to the study blocks |
| E9 | Repairs measured in the lab hold on a real network over hours, with block-level intervals | 12-block evening study: triage-driven repair, local threshold and two-envelope anomaly rule vs references ([real_network](results/real_network.md)) | Capturing |

## Contributions

1. **A matched-control result** that the standard limited-label adaptation trades legitimate services for detection,
   with the source-removed control that isolates why (E3).
2. **A mechanism, not a score**: per-service and per-feature diagnosis of every false-alarm source, from confusion
   matrices on all-benign captures (E4) to feature-envelope and sensor-position analysis on live traffic (E7, E8).
3. **A repair protocol with a measured price**: local benign service flows (E5), analyst triage of the detector's own
   alerts on earlier traffic as the repair set, which the console's triage records can supply, and a label-free
   two-envelope anomaly rule (E9). Each is reported against benchmark detection, so no gain hides a loss.
4. **Real-network evidence** with privacy controls: passive capture under consent, keyed pseudonymisation, aggregates
   only, block-level intervals, and the negative findings kept (E7–E9).
5. **An honest method record**: a capture-validity finding (header-only capture corrupts 25 of 83 features), the
   non-independence of NAT'd lab traffic, and an offload hypothesis tested and rejected as the cause of alert volume.

## Threats to validity and how each is handled

| Threat | Handling |
|---|---|
| Real traffic is unlabelled | Alerts are reported as candidate false alerts (an upper bound); no attacks are generated on the home network |
| One home network, one evening | Stated as a case study; block-level bootstrap, not flow-level intervals; earlier-day sessions for fitting, later blocks for evaluation |
| Few label seeds | 10-seed replication with dose–response (0, 5, 10, 30 service flows) |
| One transfer direction | Reverse-direction replication |
| Oracle attack labels understate annotation cost | Stated; the triage condition uses only benign confirmations, which an analyst can give cheaply |
| Lab services are not a real network | E9 tests the lab-derived repair on real traffic directly |
| Novelty claims | Related-work check before any "first" claim (prompt in `reports/A2/codex/`) |

## Remaining work to 18 December 2026

| By | Work |
|---|---|
| Week 8 | Finish E5/E6 replications; complete the 12-block study and E9; run E8 on every block |
| Week 9 | Second real-network study on a different day or network for independence; related-work check |
| Week 10 | Console: triage decisions exported as repair sets; two-envelope rule as a deployable option |
| Week 11–12 | Thesis write-up from the result files; reproduce every number from a clean checkout |
