# Project Plan — AI-Based Cybersecurity Intrusion Detection and Threat Analysis Dashboard + Cloud

Target: **HD in every assessment.** Budget: **$0.**

## 1. The angle (what makes it HD rather than generic)
Most published ML intrusion detection systems (IDS):
- report about 99% accuracy on a single benchmark dataset that contains known labelling flaws, and generalise poorly to other networks
- produce black-box alerts that analysts can't interpret, which adds to SOC alert fatigue
- are out of reach for small and medium businesses (SMEs) that can't afford a commercial SIEM

**Our project:** an *explainable*, *cross-dataset-validated* IDS. It adds threat context from MITRE ATT&CK and runs on low-cost cloud infrastructure for SMEs. Each of those three gaps becomes a contribution we can measure and evaluate.

## 2. System components
| # | Component | What it does | Tools (all free) |
|---|---|---|---|
| 1 | **Data** | Benchmark flow data plus our own simulated attack traffic | CSE-CIC-IDS2018 (AWS Open Data, no account needed), CIC-IDS2017 or UNSW-NB15 for cross-dataset tests |
| 2 | **Attack lab** | Isolated VMs generating real attack traffic we capture ourselves | VirtualBox, Kali Linux to Ubuntu victim (host-only network), CICFlowMeter, Wireshark |
| 3 | **Detection models** | Supervised classifiers plus anomaly detection for unseen ("zero-day") attacks | Python, scikit-learn, XGBoost, LightGBM, Isolation Forest/autoencoder, imbalanced-learn |
| 4 | **Explainability** | Why each alert fired | SHAP |
| 5 | **Threat analysis** | Maps detections to MITRE ATT&CK techniques, severity scores and response recommendations | MITRE ATT&CK (free), rule layer; optional local LLM summaries (Ollama) |
| 6 | **API** | Serves predictions and alerts | FastAPI, SQLite |
| 7 | **Dashboard** | Live alerts, attack breakdown, SHAP explanations, model metrics, ATT&CK view | Streamlit + Plotly |
| 8 | **Cloud** | Hosted dashboard and API, data storage, monitoring | Docker, Azure for Students (or AWS free plan) |
| 9 | **Engineering** | Version control, tests, CI | GitHub, pytest, GitHub Actions |

## 3. Cost
| Item | Cost |
|---|---|
| Datasets (CIC, UNSW) | $0 |
| VirtualBox, Kali, Ubuntu, CICFlowMeter, Wireshark | $0 |
| Python and all ML libraries | $0 |
| Model training (laptop or Google Colab free tier) | $0 |
| GitHub (plus Student Developer Pack) | $0 |
| Cloud: Azure for Students, US$100 credit, no card, renews yearly | $0 (expected use under $20 of credit) |
| Diagrams (draw.io), references (Zotero), slides (PowerPoint/Google Slides) | $0 |
| **Total out of pocket** | **$0** |

Cost safeguards: set a budget alert at $10, use the smallest instance size, stop or delete resources after demos, and never use paid managed services (e.g. Azure ML compute, SageMaker endpoints).

## 4. Timeline (Week 3 ends Sun 18 Oct, so today, Tue 6 Oct, is Week 2)
| Week | Dates | Project work | Assessment |
|---|---|---|---|
| 2 | 5–11 Oct | Kickoff meeting (roles, leaders), repo + AGENTS.md, meeting log, literature search (10+ sources), dataset download, A1 draft | |
| 3 | 12–18 Oct | Data pipeline + exploratory analysis; finalise A1 | **A1 Brief, Sun 18 Oct** |
| 4 | 19–25 Oct | Baseline models; requirements spec; diagrams v1; expand lit review | |
| 5 | 26 Oct–1 Nov | Multi-model training, class imbalance handling | **A2.1, Sun 1 Nov** |
| 6 | 2–8 Nov | VM attack lab + traffic capture; FastAPI; sequence diagrams | |
| 7 | 9–15 Nov | Dashboard v1; cloud account + deployment skeleton; test plan | **A2.2, Sun 15 Nov** |
| 8 | 16–22 Nov | SHAP, anomaly detection, cross-dataset evaluation, ATT&CK mapping; cloud deploy | |
| 9 | 23–29 Nov | Results, charts, interpretation | **A2.3, Sun 29 Nov** |
| 10 | 30 Nov–6 Dec | Hardening, testing, false-positive analysis; slides; rehearsals; start A4 | |
| 11 | 7–13 Dec | Live presentation + demo; A4 drafting | **A3 Presentation** |
| 12 | 14–18 Dec | Final edits | **A4 Report, Fri 18 Dec** |

*Check whether the term has a mid-semester break that shifts the week numbers.*

**Feature freeze: end of Week 9.** After that, only fixes and polish.

## 5. Team and leadership (each member leads at least one milestone)
Team: **3 members** (the third joined in Week 3). Names are kept locally in `private/TEAM.md`.

| Member | Role | Leads (milestones) |
|---|---|---|
| Member A | Project Lead; Data & ML Lead | M1 brief, M4 models and evaluation (SHAP), M7 final report; data pipeline |
| Member B | Security & Cloud Lead | M3 attack lab and data-collection plan, M6 presentation and demo; ATT&CK mapping, ethics/compliance, Azure deployment and hardening |
| Member C | Research & Platform Lead | M2 requirements and literature review, M5 dashboard and interim results; API, dashboard, testing |

Shared: meeting minutes (alternating chair and minute-taker), testing, rehearsals.

## 6. Claude Code vs Codex CLI
- **Claude Code:** specs, architecture and diagrams, cloud setup, report drafting, reference verification, reviewing Codex's code
- **Codex CLI:** implementing modules from specs in `docs/`, writing tests
- Both read `AGENTS.md` plus `docs/` and work in one git repo, one feature branch at a time.

## 7. Ethics and compliance thread (runs through every assessment)
- Attacks only in an isolated, self-owned lab; never on real networks.
- Public, anonymised datasets; no personal data collected.
- Australian Privacy Act 1988 / APPs, Notifiable Data Breaches scheme, ASD Essential Eight, ISO/IEC 27001, NIST CSF 2.0, ACS Code of Professional Conduct.
- Transparency (SHAP), fairness (false-positive impact), sustainability (small models, auto-shutdown cloud).
- AI-use declaration on every cover sheet.
