# Related work and what is new

Positioning of the thesis claims in [`THESIS.md`](THESIS.md) against work from 2019–2026. The sweep (31 October 2026)
used OpenAlex title/abstract search plus limited web search. Every DOI below was resolved and its metadata checked.
Several of the closest items are 2026 preprints or repository deposits that are **not peer reviewed**; they are
marked †. Descriptions are based on abstracts and must be checked against the full text before a specific number
is quoted in the thesis. "Not found" means not found in this sweep, not proof of absence.

## Claim by claim

| Thesis link | Closest prior work | What it already shows | What this project adds |
|---|---|---|---|
| **E3** Limited-label adaptation breaks legitimate services; matched target-only control | Rayamajhi (2026)†; Vu et al. (2026)†; Lawall & Zöller (2025); Sudyana et al. (2026) | A target-only control at matched label budget already exists: on NetFlow-v3 benchmarks the source helped in few comparisons and hurt in more (Rayamajhi†). Uncertainty-based label selection can fall below no adaptation (Vu et al.†). Adding benign target data gave no marked gain on the CIC pair (Lawall & Zöller). Source-free adaptation reduces benign false positives, compared against no adaptation only (Sudyana et al.). | The control is **not new**; we cite it and agree with it. New: the outcome is **false alerts on legitimate services** rather than F1/AUROC, in the CICFlowMeter feature space on the corrected CIC-IDS2017 → CSE-CIC-IDS2018 pair, with the mechanism (which services fail, and as which attack). |
| **E4–E5** Service-concentrated classifier failure; about one benign flow per service repairs it | D'hooge et al. (2022); Pillai et al. (2026); Vu et al. (2026)†; Komisarek et al. (2021) | Port and other metadata act as shortcut features (D'hooge et al.). The CIC cross-network failure is driven by environment-encoding features such as initial window size (Pillai et al.). Repair budgets reported elsewhere are larger and flow-based: 10–20 selected labels (Vu et al.†), "a small amount" of end-user data (Komisarek et al.). | Not found: false alarms aggregated **by destination service**, shown to be whole-service in a controlled capture, with a repair budget that scales with **the number of services** (18 flows, 10 seeds). Because port is a known shortcut, the repair is re-run **without port and window features** ([`service_repair_*_portable`](results/)) so the claim does not rest on the shortcut. |
| **E6, E7, E9** The anomaly layer flags ordinary modern transfers outside the benchmark's benign envelope; a local exemplar veto repairs it | Layeghy et al. (2024); Han et al. (2023); Layeghy et al. (2023); Engelen et al. (2021); Flood et al. (2024); Bergman et al. (2020) | Benchmark benign traffic is statistically unlike production networks (Layeghy et al., 2024). Normality shift especially harms benign-only detectors; OWAD adapts at distribution level (Han et al.). Benchmark generation limits benign diversity (Engelen et al.; Flood et al.). Plain nearest-neighbour is a strong anomaly baseline, shown on images (Bergman et al.). | Not found: attributing false alarms to **ordinary bulk transfers exceeding the benchmark's per-feature benign range** (11.5 vs 2.0 features out of range on 3,307 real flows); a **nearest-normal veto layered on a benchmark-fitted detector**; and evidence, in both transfer directions and on a real network, that it leaves attack detection unchanged. Han et al. (OWAD) is the method to compare against. |
| **E6** Analyst triage of false alarms as the classifier's repair set | Siddiqui et al. (2019); Das et al. (2024); Andresini et al. (2021); Vu et al. (2026)†; Alahmadi et al. (2022) | Analyst true/false-positive feedback improves an unsupervised detector on one network (Siddiqui et al.; Das et al.). Active learning addresses drift in NIDS (Andresini et al.). Which target flows to label after transfer (Vu et al.†). Analysts attribute most alarms to benign triggers (Alahmadi et al.). | Not found: the **triaged false-alarm stream itself** as the repair set for a **supervised flow classifier after cross-network transfer**, compared with port-stratified selection at a matched budget, in the lab and on a real network. Uncertainty sampling (Vu et al.†) is the missing comparison arm. |
| **E8** Sensor position / NIC offload changes verdicts | Soylu (2026)†; Rassam & Al-Asaly (2026); Pinto et al. (2025); Janati Idrissi et al. (2024); Alikhanov et al. (2021); Rosay et al. (2022) | Disabling GSO/TSO removed oversized-frame artefacts but did not fix cross-capture threshold transfer (Soylu†). Flow-exporter provenance, exporter choice, timeouts and sampling all change results (Rassam & Al-Asaly; Pinto et al.; Janati Idrissi et al.; Alikhanov et al.). CICFlowMeter has documented feature bugs (Rosay et al.). | Not found in peer-reviewed work: a **paired counterfactual** on the same traffic counting **verdict flips** of a CIC-trained model. Our result (classifier alerts −20%, anomaly alerts +66%, McNemar p = 6 × 10⁻¹⁰) is consistent with Soylu's "real but not decisive": offload shifts verdicts in both directions rather than explaining transfer failure. |

## What the thesis must therefore say

1. **Do not claim the target-only control as new** (E3). Claim the benign-service outcome and the mechanism.
2. **Show the service result is not a port shortcut** (E4–E5) using the portable-feature rerun.
3. **Compare the exemplar veto with OWAD-style adaptation** or justify why not (E6, E9). This is the strongest novelty
   claim and the one a reviewer will press hardest.
4. **Add uncertainty sampling as a third selection arm** beside triage and port-stratified (E6).
5. Frame offload (E8) as a **measured test**, citing Soylu† as the only direct prior result.

## References

Reference details below were taken from each DOI's registered metadata (31 October 2026), not typed from memory.

Alahmadi, B. A., Axon, L., & Martinovic, I. (2022). 99% false positives: A qualitative study of SOC analysts' perspectives on security alarms. In *31st USENIX Security Symposium* (pp. 2783–2800). USENIX Association. https://www.usenix.org/conference/usenixsecurity22/presentation/alahmadi

Alikhanov, J., Jang, R., Abuhamad, M., Mohaisen, D., Nyang, D., & Noh, Y. (2022). Investigating the effect of traffic sampling on machine learning-based network intrusion detection approaches. *IEEE Access, 10*, 5801–5823. https://doi.org/10.1109/ACCESS.2021.3137318

Andresini, G., Pendlebury, F., Pierazzi, F., Loglisci, C., Appice, A., & Cavallaro, L. (2021). INSOMNIA. In *Proceedings of the 14th ACM Workshop on Artificial Intelligence and Security* (pp. 111–122). ACM. https://doi.org/10.1145/3474369.3486864

Bergman, L., Cohen, N., & Hoshen, Y. (2020). *Deep nearest neighbor anomaly detection* [Preprint]. arXiv. https://doi.org/10.48550/arXiv.2002.10445

Das, S., Islam, M. R., Kannappan Jayakodi, N., & Doppa, J. R. (2024). Effectiveness of tree-based ensembles for anomaly discovery: Insights, batch and streaming active learning. *Journal of Artificial Intelligence Research, 80*, 127–170. https://doi.org/10.1613/jair.1.14741

D'hooge, L., Verkerken, M., Volckaert, B., Wauters, T., & De Turck, F. (2022). Establishing the contaminating effect of metadata feature inclusion in machine-learned network intrusion detection models. In *Detection of Intrusions and Malware, and Vulnerability Assessment* (pp. 23–41). Springer. https://doi.org/10.1007/978-3-031-09484-2_2

Engelen, G., Rimmer, V., & Joosen, W. (2021). Troubleshooting an intrusion detection dataset: The CICIDS2017 case study. In *2021 IEEE Security and Privacy Workshops (SPW)* (pp. 7–12). IEEE. https://doi.org/10.1109/SPW53761.2021.00009

Flood, R., Engelen, G., Aspinall, D., & Desmet, L. (2024). Bad design smells in benchmark NIDS datasets. In *2024 IEEE 9th European Symposium on Security and Privacy (EuroS&P)* (pp. 658–675). IEEE. https://doi.org/10.1109/EuroSP60621.2024.00042

Han, D., Wang, Z., Chen, W., Wang, K., Yu, R., Wang, S., Zhang, H., Wang, Z., Jin, M., Yang, J., Shi, X., & Yin, X. (2023). Anomaly detection in the open world: Normality shift detection, explanation, and adaptation. In *Proceedings 2023 Network and Distributed System Security Symposium*. Internet Society. https://doi.org/10.14722/ndss.2023.24830

Janati Idrissi, M., Alami, H., El Mahdaouy, A., Bouayad, A., Yartaoui, Z., & Berrada, I. (2025). Flow timeout matters: Investigating the impact of active and idle timeouts on the performance of machine learning models in detecting security threats. *Future Generation Computer Systems, 166*, Article 107641. https://doi.org/10.1016/j.future.2024.107641

Komisarek, M., Pawlicki, M., Kozik, R., Hołubowicz, W., & Choraś, M. (2021). How to effectively collect and process network data for intrusion detection? *Entropy, 23*(11), Article 1532. https://doi.org/10.3390/e23111532

Lawall, A., & Zöller, T. (2025). Impact of target network-specific data on the performance of machine-learning-based intrusion detection system models. In *2025 5th Intelligent Cybersecurity Conference (ICSC)* (pp. 290–297). IEEE. https://doi.org/10.1109/ICSC65596.2025.11140289

Layeghy, S., Baktashmotlagh, M., & Portmann, M. (2023). DI-NIDS: Domain invariant network intrusion detection system. *Knowledge-Based Systems, 273*, Article 110626. https://doi.org/10.1016/j.knosys.2023.110626

Layeghy, S., Gallagher, M., & Portmann, M. (2024). Benchmarking the benchmark — Comparing synthetic and real-world network IDS datasets. *Journal of Information Security and Applications, 80*, Article 103689. https://doi.org/10.1016/j.jisa.2023.103689

Pillai, N., Sawant, A., & Sanghera, K. (2026). Cross-network generalization failure in machine learning-based network intrusion detection. *Journal of Student-Scientists' Research, 8*. https://doi.org/10.13021/jssr2026.5698

Pinto, D., Vitorino, J., Maia, E., Amorim, I., & Praça, I. (2025). Flow exporter impact on intelligent intrusion detection systems. In *Proceedings of the 11th International Conference on Information Systems Security and Privacy* (pp. 289–298). SCITEPRESS. https://doi.org/10.5220/0013131900003899

Rassam, M. A., & Alasaly, M. (2026). Flow exporter provenance as a major confounder in cross-dataset IoT intrusion detection. *Mathematics, 14*(19), Article 3549. https://doi.org/10.3390/math14193549

Rayamajhi, R. (2026). *Is it transfer? A target-only control finds no consistent source benefit in few-shot cross-dataset intrusion detection on NetFlow* [Preprint]. Preprints.org. https://doi.org/10.20944/preprints202610.1041.v1

Rosay, A., Cheval, E., Carlier, F., & Leroux, P. (2022). Network intrusion detection: A comprehensive analysis of CIC-IDS2017. In *Proceedings of the 8th International Conference on Information Systems Security and Privacy* (pp. 25–36). SCITEPRESS. https://doi.org/10.5220/0010774000003120

Siddiqui, M. A., Stokes, J. W., Seifert, C., Argyle, E., McCann, R., Neil, J., & Carroll, J. (2019). Detecting cyber attacks using anomaly detection with explanations and expert feedback. In *ICASSP 2019 – 2019 IEEE International Conference on Acoustics, Speech and Signal Processing* (pp. 2872–2876). IEEE. https://doi.org/10.1109/ICASSP.2019.8683212

Soylu, M. (2026). *Benchmark-to-deployment gaps in intrusion detection system evaluation under temporal and telemetry shift* [Unreviewed deposit]. Zenodo. https://doi.org/10.5281/zenodo.21419352

Sudyana, D., Xuan, W. Y., D'hooge, L., Hwang, R.-H., Lee, N.-Y., Chen, P.-Y., Wauters, T., Volckaert, B., & De Turck, F. (2026). Bridging training–deployment gap in intrusion detection with source-free domain adaptation. *IEEE Transactions on Network and Service Management, 23*, 6982–6996. https://doi.org/10.1109/TNSM.2026.3723866

Vu, T. D., Do, X. C., & Nguyen, L. G. (2026). *Predictive inversion in cross-network intrusion detection: Which flows to label when confidence cannot be trusted* [Preprint]. Zenodo. https://doi.org/10.5281/zenodo.21900280
