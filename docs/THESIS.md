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
| E3 | A few labelled local attacks restore detection but break legitimate services | k = 50: detection 0.98, service false alerts 30–61% (26–70% at k = 200); matched target-only control 100% ([multi_env_matched](results/multi_env_matched.md)) | Measured |
| E4 | Classifier breakage is concentrated by service, and is behaviour rather than a port shortcut | Lab: whole services flagged (port 22 → SSH-BruteForce, FTP data → PortScan). Real network: concentrated on HTTPS, NAT-PMP, SSDP and mDNS but no service flagged entirely Without port and window features FTP data is still flagged as a whole service ([service_aware](results/service_aware.md), [real_network](results/real_network.md), [portable](results/service_repair_forward_portable.md)) | Measured; whole-service in the lab only |
| E5 | About one benign flow per service repairs the classifier at no detection cost | 10 seeds: held-out 38.5% → 0/3,300 with 18 flows (upper bound 0.11%); 15 flows fails on 1 seed in 10; detection 0.981 → 0.982, Wilcoxon p = 0.19 ([service_aware_seeds](results/service_aware_seeds.md)) | Measured, 10 seeds |
| E6 | Triage-chosen flows repair the classifier in both directions; the reverse direction's anomaly failure is a TCP-window fingerprint | 2018 → 2017: classifier repair alone leaves 23–31%; with exemplar envelope, triaged flows clean 5/5 seeds held-in; isolation-forest envelope only 3/5; triage 5/5 in both directions Without fingerprint features, 18 triaged flows clean 5/5 seeds held-in and held-out in both directions with no envelope ([service_repair_reverse](results/service_repair_reverse.md), [service_repair_reverse_portable](results/service_repair_reverse_portable.md)) | Measured, 5 seeds |
| E7 | On a real network the anomaly layer flags ordinary transfers because they exceed the benchmark's benign envelope | 3,307 flows: anomaly-only alerts outside the range on 11.5 features against 2.0 for quiet flows ([envelope_audit_study](results/envelope_audit_study.md)) | Measured, 12 blocks |
| E8 | Sensor position systematically shifts verdicts | Undoing segmentation offload on 13 captures: classifier alerts 93 → 74, anomaly-only 115 → 191, total 6.0% → 8.1%, McNemar p = 6 × 10⁻¹⁰, identical at 1/12/100 µs spacing ([offload_counterfactual_12us](results/offload_counterfactual_12us.md)) | Measured, 13 captures |
| E9 | The local recipe holds on a real network; a lab repair does not | 12 blocks, local flows from the previous day: 254 → 66 alerts per hour, lower in 12/12 blocks (sign test p = 0.0005), detection 0.980 → 0.980; lab service flows worse in 11/12 blocks. Without fingerprint features: 6.9% → 2.0%, 12/12 blocks, detection 0.962 → 0.958; lab flows neutral ([real_network](results/real_network.md), [real_network_portable](results/real_network_portable.md)). **Pre-registered day 2** (untouched, 4,634 flows): 6.6% → 2.0% without fingerprint features and 6.2% → 1.0% with them, 12/12 blocks each (p = 0.0005), detection change −0.002 / +0.001; lab flows neutral / worse ([real_network_day2_portable](results/real_network_day2_portable.md), [PREREGISTRATION_DAY2](PREREGISTRATION_DAY2.md)) | Confirmed on a second evening, one network |
| E10 | The triage loop is the repair's attack surface; a local-normal gate closes it; the local veto costs almost nothing on known attacks | 792 isolated-lab attack flows, 5 seeds: the anomaly layer makes no lab and only 1–8 benchmark known-attack detections per seed (the veto removed 12 over five runs without port/window features), and 264 attacks hidden in the fit pool leave lab recall unchanged. 3 attacks wrongly dismissed in triage cut recall on other captures 86% → 55% (91% → 24% with all features); gating dismissals by the local envelope restores 86–91% with false alerts unchanged. **Pre-specified confirmation** on a new replicate and seeds 5–9: gated recall equals clean in 10/10 primary runs with every legitimate dismissal kept; with all features SSH brute force can pass the gate (2/5 seeds within 2 points at 10 dismissals). About 100 local flows suffice ([attack_retention_portable](results/attack_retention_portable.md), [gate_confirm_portable](results/gate_confirm_portable.md)) | Gate confirmed at 10 dismissals; k = 3 clause missed (poisoning 9.9 points, rule 10); SSH brute force is a known hole |
| E11 | On unseen attacks the local veto has a price, and the exemplar veto pays far less of it than a local threshold | Leave-one-class-out, rule fixed before running: of the unseen-attack flows only the anomaly layer catches, the exemplar envelope removes 32% (rule: > 10% is a cost), the local threshold 76–91%. **Pre-specified five-seed confirmation**: pooled 29.3% (all features 13.6%) against 95.4% (83.8%); exemplar pays less in 5/5 seeds. Its loss is only DoS-Slowloris and Infiltration; it keeps every Bot detection in all 10 runs ([unseen_veto_portable](results/unseen_veto_portable.md), [unseen_veto](results/unseen_veto.md), seed files 1–4) | Confirmed, 5 seeds; cost is real |

## Contributions

1. **A benign-service outcome for limited-label adaptation** (E3). The matched target-only control itself is not new
   (Rayamajhi, 2026, preprint, on NetFlow); what is added is the outcome an operator pays for, false alerts on legitimate
   services, with the mechanism, on the corrected CICFlowMeter benchmark pair.
2. **A decomposition of false alarms into separable mechanisms**, each with its own diagnostic: per-service confusion
   for the classifier (E4), a benign-envelope audit for the anomaly layer (E7), and a paired offload counterfactual for
   sensor position (E8).
3. **A repair protocol with a measured price**: analyst-confirmed benign flows chosen by triage for the classifier
   (E5, E6) and a local model of the site's normal traffic for the anomaly layer (E9). On false alerts a local threshold
   and the exemplar veto tie; on unseen attacks the exemplar veto keeps far more of the anomaly layer's detections
   (E11), which is the reason to prefer it. The triage loop that supplies the repair set can be poisoned by wrong
   dismissals, and a local-normal gate on dismissals closes that path except for attacks that resemble ordinary sessions, such as SSH brute force (E10). Every repair is reported against
   detection so no gain hides a loss.
4. **Real-network evidence** with privacy controls: passive capture under consent, keyed pseudonymisation,
   aggregates only, block-level statistics, the previous day for fitting and the next for evaluation (E7–E9).
5. **An honest method record**: header-only capture corrupts 25 of 83 features; NAT'd lab traffic is not an
   independent environment; a single-capture offload result reversed at scale; the "30 flows" figure was 37 in fact;
   and a lab-built repair made a real network worse.

## Threats to validity and how each is handled

| Threat | Handling |
|---|---|
| Real traffic is unlabelled | Alerts are reported as candidate false alerts (an upper bound); no attacks are generated on the home network |
| One home network | Stated as a case study; per-block sign tests; day-1 sessions for fitting; a second, pre-registered evening confirmed the result (H1–H4). Another network is the next step |
| Few label seeds | 10 seeds for the dose–response, 5 per direction for the repair comparison |
| One transfer direction | Both directions measured; they fail differently (E6) |
| Oracle attack labels understate annotation cost | Stated; the repair itself uses only benign confirmations, which an analyst can give cheaply |
| Lab services are not a real network | E9 tests the lab-derived repair on real traffic directly, and it fails |
| The repair could hide attacks or be poisoned | E10 tests known attacks, fit-pool poisoning, wrong dismissals and evasion toward normal; E11 tests unseen attacks, where the veto does cost detection and the price is reported |
| Counterfactual rewrite could add artefacts | Packet spacing varied 1–100 µs with no change in results |
| Port is a known shortcut feature (D'hooge et al., 2022) | Every repair experiment rerun without port and TCP window features; conclusions hold and two earlier findings were reattributed to fingerprints |
| Novelty claims | Checked against 2019–2026 work in [RELATED_WORK.md](RELATED_WORK.md); claims limited to what was not found |

## Remaining work to 18 December 2026

| By | Work |
|---|---|
| Week 8 | Second real-network study: done 1 Nov, pre-registered, all four hypotheses confirmed |
| Week 9 | Comparison arms (done): triage never worse than uncertainty sampling, better on day 2; local threshold, refit and exemplar veto not consistently separable |
| Week 10 | Done 4 Nov: confirmations C1–C3 scored as pre-specified; a three-day-old local pool repairs as well as a two-day-old one (no decay, p = 0.39; [cadence_portable](results/cadence_portable.md)) |
| Week 10 | Done 3 Nov: the console gates dismissals by the site envelope before retraining and demotes vetoed anomaly alerts to a low-priority count (E10, E11) |
| Week 11–12 | Thesis write-up from the result files; reproduce every number from a clean checkout |
