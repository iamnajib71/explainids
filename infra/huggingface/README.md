---
title: ExplainIDS
emoji: 🛡️
colorFrom: indigo
colorTo: blue
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Explainable AI intrusion detection on real network flows
---

# ExplainIDS

Explainable machine-learning intrusion detection. A LightGBM detector trained on the corrected
CIC-IDS2017 release scores **real held-out network flows**; every alert carries SHAP explanations,
a candidate MITRE ATT&CK technique and response steps, and alerts are grouped into incidents.

- **Live monitor**: replay real test traffic with ground truth and watch hits, misses and false alarms.
- **Model lab**: honest test metrics (macro F1, false-positive rate, confusion matrix).
- **Analyse a file**: upload a CICFlowMeter CSV (a labelled sample is provided).

Source, results and method: https://github.com/iamnajib71/explainids

Data: corrected CIC-IDS2017 (Engelen et al., 2021; Liu et al., 2022), original by Sharafaldin et al. (2018).
