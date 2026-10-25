# ExplainIDS research findings

Most published ML intrusion detectors report about 99% on a single benchmark. They are rarely tested on a second network, rarely asked whether their explanations are stable, and rarely tested on attacks missing from training. We asked three questions, each answered by a script in this repository on the corrected CIC-IDS2017 and CSE-CIC-IDS2018 releases (Liu et al., 2022). Every number below comes from the result file linked beside it. The console's **Findings** tab shows the same three answers.

| | Question | Answer | One-line takeaway |
|---|---|---|---|
| **RQ1** | Does a detector trained on one network work on another? | **8%** of attack flows caught after moving 2017 → 2018 (70% the other way) | Near-perfect in-domain scores do not transfer. Retrain or calibrate on local traffic before trusting it. |
| **RQ2** | Do SHAP explanations stay the same when the model is retrained? | **4 of 5** top features shared per alert (median overlap 0.67); model-wide top-10 overlap 0.82–1.0 | The "why" is stable enough to guide an analyst, but individual ranks are not. |
| **RQ3** | Can it flag an attack type it never saw in training? | **52%** median (2017), 57% with a log-scaled anomaly detector; **7%** on 2018 | Unseen attacks are mostly caught by resembling a known class. The anomaly layer helps scans, not brute force. |

Common setup: data deduplicated globally (no feature vector appears in two splits), then split chronologically per class (70/10/20); training capped at 60,000 flows per class; seed 42; LightGBM unless stated. Metrics follow project rule 4: recall, precision, F1 (macro and per class), benign false-positive rate (FPR) and confusion matrices, never accuracy alone.

---

## RQ1: Generalisation across networks

**Why it matters.** Cross-dataset failure is known (Cantone et al., 2024; Catillo et al., 2022). Verkerken et al. (2022) report Isolation Forest AUROC falling from 0.958 to 0.643 between these two datasets. D'hooge et al. (2022) argue that destination port is a benchmark shortcut that should be removed. We test both claims on the corrected releases with a supervised detector.

**Method.** [`scripts/cross_dataset_eval.py`](../scripts/cross_dataset_eval.py). Train on one dataset's training split and score both datasets' test splits, so in-domain and transfer rows share the same test flows. Macro F1 is averaged over the 12 classes both datasets contain, the same set for every row. A second run drops environment-specific features (destination port, TCP initial window sizes, minimum segment size). Result: [`results/cross_dataset.md`](results/cross_dataset.md).

| Train → test | Attacks caught (recall) | Benign FPR | Macro F1 (12 common classes) |
|---|---|---|---|
| 2017 → 2017 | 99.8% | 0.55% | 0.89 |
| **2017 → 2018** | **8.2%** | 3.02% | 0.58 |
| **2018 → 2017** | **70.3%** | 1.34% | 0.34 |
| 2018 → 2018 | 99.3% | 0.05% | 0.95 |
| 2017 → 2018, portable features | 1.5% | 2.82% | 0.35 |
| 2018 → 2017, portable features | 65.6% | 1.00% | 0.34 |

**What we found.**
- **The collapse is concentrated in two attack tools.** 2017 → 2018 detects 0% of DoS-Hulk and DDoS-HTTP flows, which make up most attack traffic in 2018. Other classes transfer well: SSH brute force 100%, Bot 100%, Web-BruteForce 96%, Web-XSS 96%, DoS-Slowloris 93%.
- **Detection is not attribution.** 2018 → 2017 flags 79% of DoS-Hulk flows but labels almost none correctly (F1 0.00). It calls them other DoS classes, so recall stays high while macro F1 falls.
- **Removing the "shortcut" features made transfer worse, not better** (8.2% → 1.5%). This points to a real difference in how the same tools' traffic looks in each capture, rather than reliance on port numbers. This qualifies D'hooge et al.'s recommendation: dropping metadata features is sound hygiene, but it does not by itself buy generalisation.
- **The model's reasoning shifts with the data.** The global SHAP top-10 for the same model overlaps only 0.82 (2017 model) and 0.67 (2018 model) between its own test set and the other dataset. That is consistent with Layeghy and Portmann (2023).

**Limits.** 2018 benign traffic is a 5% random sample, which makes alert precision optimistic; recall and FPR are unaffected. Two corrected CIC captures share a lab design, so this is a lower bound on how hard a real new network would be.

## RQ2: Stability of explanations

**Why it matters.** An explanation an analyst acts on should not change just because the model was retrained. Lin and Wang (2025) found top-5 SHAP rankings highly concordant across 100 seeds in credit scoring (Kendall's W = 0.93), but much less so further down the ranking. We test the same idea on network flows.

**Method.** [`scripts/shap_stability_eval.py`](../scripts/shap_stability_eval.py) (drafted by Codex CLI, reviewed). The same 500 test attack flows are explained by five LightGBM models that differ only in training seed (with bagging, so the seed matters). We compare each flow's top-5 SHAP features between models with Jaccard overlap, only when both models predict the same class. Result: [`results/shap_stability_cicids2017.md`](results/shap_stability_cicids2017.md).

| Measure | Result |
|---|---|
| Per-alert top-5 overlap, median (10th percentile) | **0.67** (0.43); 0.67 means 4 of 5 features shared |
| Prediction changed between seeds | 0 of 5,000 flow pairs |
| Most stable classes | PortScan and SSH brute force: median overlap 1.00 |
| Model-wide top-10 overlap / Spearman rank correlation | 0.82–1.00 / 0.87–0.98 |
| Macro F1 / benign FPR across seeds | 0.88–0.91 / 0.54–0.56% |

**What we found.** The explanation an analyst sees is substantially, but not perfectly, repeatable: typically one of the five reasons changes between retrains. Global importance is more stable than per-alert detail, which matches the pattern Lin and Wang (2025) report for less important features. In practice the console should present the top contributors as a group and not over-interpret their order. Following Loecher (2024), stable does not mean correct; it means repeatable model behaviour.

**Side finding.** The bagged models (row and feature subsampling at 0.8) reach macro F1 0.88–0.91, against 0.86 for the baseline configuration. This is a candidate improvement for the deployed model, to be confirmed on validation data before adoption.

## RQ3: Attacks never seen in training

**Why it matters.** "Detects zero-day attacks" is a common claim. Sarhan et al. (2023) used this exact leave-one-attack-out protocol on UNSW-NB15 and report 87–92% average detection of the withheld class.

**Method.** [`scripts/unseen_attack_eval.py`](../scripts/unseen_attack_eval.py). For each attack class, remove it from training and validation, train the classifier plus a benign-only Isolation Forest (threshold set for 1% false alarms on validation benign traffic), then score every flow of that class. A flow counts as caught if the classifier calls it any attack or the Isolation Forest flags it. Results: [`unseen_cicids2017`](results/unseen_cicids2017.md), [`unseen_cicids2017_log`](results/unseen_cicids2017_log.md), [`unseen_csecicids2018`](results/unseen_csecicids2018.md), [`unseen_csecicids2018_log`](results/unseen_csecicids2018_log.md).

| Dataset | Anomaly detector input | Median detection of unseen class | Classes ≥ 90% | Benign FPR |
|---|---|---|---|---|
| 2017 (14 classes) | raw features | 52% | 3 | 1.0–1.6% |
| 2017 | signed-log features | **57%** | 3 | **0.7–1.1%** |
| 2018 (12 classes) | raw features | 7% | 2 | 0.9% |
| 2018 | signed-log features | 4% | 2 | 1.0% |

**What we found.**
- **Unseen attacks are mostly caught by resemblance.** Unseen DDoS is flagged as DoS-Hulk, unseen Slowloris as SlowHTTPTest, unseen XSS as web brute force. These are useful alerts in the right ATT&CK family, but the classifier cannot say "this is new".
- **The anomaly layer barely helped on raw features.** Flow features are extremely skewed: 56 of 83 have skewness above 5 ([EDA notebook](../notebooks/01_eda_cicids2017.ipynb)). So we tested a signed-log transform before the Isolation Forest. On 2017 it lifted unseen **PortScan from 0% to 93%**, raised the median from 52% to 57%, and *lowered* false alarms. It slightly hurt Bot (6% → 1%) and Infiltration (47% → 39%).
- **Brute force and bots stay invisible.** FTP and SSH brute force and Bot remain near 0% on both datasets: individually they look like ordinary short connections. Per-flow features cannot see them; this points to session- or host-level aggregation as future work.
- **The gap to Sarhan et al. is large.** On 2018 the median is only 7%: there, the DoS family transfers internally, but most other classes are missed.

**Limits.** The unseen rate uses every flow of the withheld class, while the "seen" reference in the result files uses that class's test split and the classifier alone, so the two are not a paired comparison. Classes with fewer than 20 flows (e.g. Heartbleed, 11) give very coarse percentages.

---

## How each problem was found and fixed

| Problem | How we found it | What we changed | Effect |
|---|---|---|---|
| Identical flows in training and test (leakage) | Codex CLI code review: 2,891 test flows matched training vectors | Global deduplication before splitting ([`ids.data.dedup_global`](../src/ids/data.py)); vectors seen with two labels dropped | 2017 macro F1 0.872 → 0.862 (the honest figure) |
| Cross-dataset rows averaged over different classes | Codex dashboard review | Macro F1 over one common class set for every row | In-domain and transfer scores are now comparable |
| Anomaly layer blind on skewed features | RQ3 results plus EDA skewness | Optional signed-log input (`Detector(anomaly_log=True)`) | Unseen PortScan 0% → 93% at a lower false-alarm rate |
| Port "shortcut" suspected (D'hooge et al., 2022) | Literature | Portable feature-set ablation | Not the cause here; transfer got worse without these features |

## Reproduce
```bash
python scripts/build_processed.py data/raw/cicids2017 data/processed/cicids2017.parquet
python scripts/build_sampled.py data/raw/csecicids2018 data/processed/csecicids2018.parquet --benign-frac 0.05
python scripts/cross_dataset_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet --results docs/results/cross_dataset.md
python scripts/shap_stability_eval.py data/processed/cicids2017.parquet --seeds 42,1,2,3,4 --results docs/results/shap_stability_cicids2017.md
python scripts/unseen_attack_eval.py data/processed/cicids2017.parquet [--anomaly-log] --results docs/results/unseen_cicids2017.md
python scripts/build_research_summary.py   # refreshes the console's Findings tab
```

## References
Cantone, M., Marrocco, C., & Bria, A. (2024). Machine learning in network intrusion detection: A cross-dataset generalization study. *IEEE Access, 12*, 144489–144508. https://doi.org/10.1109/ACCESS.2024.3472907

Catillo, M., Del Vecchio, A., Pecchia, A., & Villano, U. (2022). Transferability of machine learning models learned from public intrusion detection datasets: The CICIDS2017 case study. *Software Quality Journal, 30*(4), 955–981. https://doi.org/10.1007/s11219-022-09587-0

D'hooge, L., Verkerken, M., Volckaert, B., Wauters, T., & De Turck, F. (2022). Establishing the contaminating effect of metadata feature inclusion in machine-learned network intrusion detection models. In *Detection of Intrusions and Malware, and Vulnerability Assessment* (pp. 23–41). Springer. https://doi.org/10.1007/978-3-031-09484-2_2

Layeghy, S., & Portmann, M. (2023). Explainable cross-domain evaluation of ML-based network intrusion detection systems. *Computers and Electrical Engineering, 108*, Article 108692. https://doi.org/10.1016/j.compeleceng.2023.108692

Lin, L., & Wang, Y. (2025). SHAP stability in credit risk management: A case study in credit card default model. *Risks, 13*(12), Article 238. https://doi.org/10.3390/risks13120238

Liu, L., Engelen, G., Lynar, T., Essam, D., & Joosen, W. (2022). Error prevalence in NIDS datasets: A case study on CIC-IDS-2017 and CSE-CIC-IDS-2018. In *2022 IEEE Conference on Communications and Network Security (CNS)* (pp. 254–262). IEEE. https://doi.org/10.1109/CNS56114.2022.9947235

Loecher, M. (2024). Debiasing SHAP scores in random forests. *AStA Advances in Statistical Analysis, 108*(2), 427–440. https://doi.org/10.1007/s10182-023-00479-7

Sarhan, M., Layeghy, S., Gallagher, M., & Portmann, M. (2023). From zero-shot machine learning to zero-day attack detection. *International Journal of Information Security, 22*(4), 947–959. https://doi.org/10.1007/s10207-023-00676-0

Verkerken, M., D'hooge, L., Wauters, T., Volckaert, B., & De Turck, F. (2022). Towards model generalization for intrusion detection: Unsupervised machine learning techniques. *Journal of Network and Systems Management, 30*(1), Article 12. https://doi.org/10.1007/s10922-021-09615-7
