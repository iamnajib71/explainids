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

> A benchmark-trained detector's false alarms on a new network are not diffuse noise. They come from separable
> mechanisms: classifier errors concentrated by service, an anomaly envelope that ordinary modern traffic exceeds,
> and a sensor-position dependence that shifts verdicts between the two. Each mechanism can be diagnosed from
> unlabelled local traffic and has a label-cheap local repair whose cost on attack detection is measured: a handful of
> analyst-confirmed benign flows per service for the classifier, and an exemplar envelope of the site's own normal
> traffic for the anomaly layer. The common shortcut, a few labelled local attacks, restores detection but amplifies
> the first mechanism, and a repair built in a lab does not carry over to a real network.

## Evidence chain

Each link is a script in this repository with a committed result file.

| # | Claim | Evidence | Status |
|---|---|---|---|
| E1 | Benchmark scores do not transfer between networks | 2017 → 2018 catches 8.2% of attacks; 2018 → 2017 70.3% ([cross_dataset](results/cross_dataset.md)) | Measured |
| E2 | Local benign traffic restores the false-alarm budget but not detection | 1,000 local flows: FPR 3.4% → 1.2%, detection 0.55 → 0.32 ([local_calibration](results/local_calibration.md)) | Measured |
| E3 | A few labelled local attacks restore detection but break legitimate services | k = 50: detection 0.98, service false alerts 26–70%; matched target-only control 100% ([multi_env_matched](results/multi_env_matched.md)) | Measured |
| E4 | Classifier breakage is concentrated by service | Lab: whole services flagged (port 22 → SSH-BruteForce, FTP data → PortScan). Real network: concentrated on HTTPS, NAT-PMP, SSDP and mDNS but no service flagged entirely ([service_aware](results/service_aware.md), [real_network](results/real_network.md)) | Measured; whole-service in the lab only |
| E5 | About one benign flow per service repairs the classifier at no detection cost | 10 seeds: held-out 38.5% → 0/3,300 with 18 flows (upper bound 0.11%); 15 flows fails on 1 seed in 10; detection 0.981 → 0.982, Wilcoxon p = 0.19 ([service_aware_seeds](results/service_aware_seeds.md)) | Measured, 10 seeds |
| E6 | In the reverse direction the anomaly envelope is a second, separate failure; an exemplar envelope repairs it | 2018 → 2017: classifier repair alone leaves 23–31%; with exemplar envelope, triaged flows clean 5/5 seeds held-in; isolation-forest envelope only 3/5; triage 5/5 in both directions ([service_repair_reverse](results/service_repair_reverse.md), [service_repair_forward](results/service_repair_forward.md)) | Measured, 5 seeds |
| E7 | On a real network the anomaly layer flags ordinary transfers because they exceed the benchmark's benign envelope | 3,307 flows: anomaly-only alerts outside the range on 11.5 features against 2.0 for quiet flows ([envelope_audit_study](results/envelope_audit_study.md)) | Measured, 12 blocks |
| E8 | Sensor position systematically shifts verdicts | Undoing segmentation offload on 13 captures: classifier alerts 93 → 74, anomaly-only 115 → 191, total 6.0% → 8.1%, McNemar p = 6 × 10⁻¹⁰, identical at 1/12/100 µs spacing ([offload_counterfactual_12us](results/offload_counterfactual_12us.md)) | Measured, 13 captures |
| E9 | The local recipe holds on a real network; a lab repair does not | 12 blocks, local flows from the previous day: 254 → 66 alerts per hour, lower in 12/12 blocks (sign test p = 0.0005), detection 0.980 → 0.980; lab service flows worse in 11/12 blocks ([real_network](results/real_network.md)) | Measured, one network, one evening |

## Contributions

1. **A matched-control result** that the standard limited-label adaptation trades legitimate services for detection,
   with the source-removed control that isolates why (E3).
2. **A decomposition of false alarms into separable mechanisms**, each with its own diagnostic: per-service confusion
   for the classifier (E4), a benign-envelope audit for the anomaly layer (E7), and a paired offload counterfactual for
   sensor position (E8).
3. **A repair protocol with a measured price**: analyst-confirmed benign flows chosen by triage for the classifier
   (E5, E6) and an exemplar envelope of local normal traffic for the anomaly layer (E6, E9), each reported against
   benchmark detection so no gain hides a loss. The console's triage records can supply the repair set directly.
4. **Real-network evidence** with privacy controls: passive capture under consent, keyed pseudonymisation,
   aggregates only, block-level statistics, the previous day for fitting and the next for evaluation (E7–E9).
5. **An honest method record**: header-only capture corrupts 25 of 83 features; NAT'd lab traffic is not an
   independent environment; a single-capture offload result reversed at scale; the "30 flows" figure was 37 in fact;
   and a lab-built repair made a real network worse.

## Threats to validity and how each is handled

| Threat | Handling |
|---|---|
| Real traffic is unlabelled | Alerts are reported as candidate false alerts (an upper bound); no attacks are generated on the home network |
| One home network, one evening | Stated as a case study; per-block sign tests; previous-day sessions for fitting, later blocks for evaluation. A second study on another day or network is the next step |
| Few label seeds | 10 seeds for the dose–response, 5 per direction for the repair comparison |
| One transfer direction | Both directions measured; they fail differently (E6) |
| Oracle attack labels understate annotation cost | Stated; the repair itself uses only benign confirmations, which an analyst can give cheaply |
| Lab services are not a real network | E9 tests the lab-derived repair on real traffic directly, and it fails |
| Counterfactual rewrite could add artefacts | Packet spacing varied 1–100 µs with no change in results |
| Novelty claims | Related-work check before any "first" claim |

## Remaining work to 18 December 2026

| By | Work |
|---|---|
| Week 8 | Related-work check against E3–E9; second real-network study on another day (independence) |
| Week 9 | Real-network seeds and k sensitivity; feed console triage decisions into the repair set |
| Week 10 | Exemplar envelope as a deployable console option, with its alert budget shown |
| Week 11–12 | Thesis write-up from the result files; reproduce every number from a clean checkout |
