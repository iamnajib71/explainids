# Work Breakdown — everything to be done

Owner key: **Y** = Data & ML Lead, **K** = Security & Cloud Lead, **P** = Research & Platform Lead (joined Week 3; API, dashboard and testing), **C** = Claude Code, **X** = Codex CLI. "Y/K" means the named role leads and reviews while the AI drafts or builds.

## A. Admin & teamwork (ongoing)
| # | Task | Owner | When |
|---|---|---|---|
| A1 | Email Unit Coordinator about team size; keep the reply | Y | This week |
| A2 | Sign up for Azure for Students (all members) | Y, K, P | Week 2–3 |
| A3 | Weekly meeting (about 30 min); minutes in template, alternating chair | Y, K | Every week |
| A4 | Leadership log: what each person led, decisions, challenges | Y, K | Every week |
| A5 | Evidence folder: screenshots, git history, chat logs, task board | Y, K | Ongoing |
| A6 | Cover sheet + AI Declaration for every submission | Y/K | Each due date |

## B. Build (the technical project)
| # | Component | Lead | Builder | Done by |
|---|---|---|---|---|
| B1 | Repo, folder structure, AGENTS.md, GitHub, CI | Y | C | Week 2 |
| B2 | Download datasets (CSE-CIC-IDS2018 + CIC-IDS2017/UNSW-NB15) | Y | C | Week 3 |
| B3 | Data pipeline: cleaning, deduplication, feature selection, stratified sampling | Y | X | Week 3 |
| B4 | Exploratory data analysis notebook + charts | Y | X | Week 4 |
| B5 | Baseline models (Random Forest, Logistic Regression) | Y | X | Week 4 |
| B6 | Advanced models (XGBoost, LightGBM) + class-imbalance handling | Y | X | Week 5 |
| B7 | VM attack lab: VirtualBox, Kali to Ubuntu, host-only network | K | C (guide) | Week 6 |
| B8 | Run attacks (port scan, brute force, DoS) and capture flows with CICFlowMeter | K | K | Week 6 |
| B9 | FastAPI service: /predict, /alerts, /metrics | P | X | Week 6 |
| B10 | Streamlit dashboard v1: alerts, attack breakdown, metrics | P | X | Week 7 |
| B11 | Docker + Azure deployment skeleton, budget alert | K | C | Week 7 |
| B12 | Anomaly detection (Isolation Forest/autoencoder) for unseen attacks | Y | X | Week 8 |
| B13 | SHAP explainability in the dashboard | Y | X | Week 8 |
| B14 | Cross-dataset evaluation + test on own lab traffic | Y | X | Week 8 |
| B15 | MITRE ATT&CK mapping, severity scoring, response playbooks | K | C | Week 8 |
| B16 | Full cloud deployment (public URL, logging, monitoring) | K | C | Week 8 |
| B17 | Testing: unit tests, API tests, load/latency test, false-positive analysis | P, Y | X | Week 9 |
| B18 | Results pack: all charts and tables for reports and slides | Y | C | Week 9 |
| B19 | Polish, bug fixes, recorded demo video (backup for live demo) | K | C | Week 10 |
| B20 | Shut down cloud resources after marking | K | K | After Week 12 |

## C. Diagrams & artefacts
| # | Artefact | Needed for |
|---|---|---|
| C1 | Conceptual framework | A1, A2.1, A3, A4 |
| C2 | System architecture (cloud) | A2.1 v1, A2.2 v2, A3, A4 |
| C3 | Data/ML pipeline flowchart | A2.1, A2.2, A4 |
| C4 | Sequence diagram (traffic, detection, alert, dashboard) | A2.2, A4 |
| C5 | Use case / process model | A2.2 |
| C6 | Attack lab network diagram | A2.2, A4 |
| C7 | Gantt chart / timeline | A1, A2.1 |
| C8 | Risk register | A1, A2.1 |
| C9 | Requirements table (functional + non-functional) | A1, A2.1 |
| C10 | Dashboard screenshots / mock-ups | A2.1 (mock-up), A2.3, A3, A4 |

## D. Research
| # | Task | Owner |
|---|---|---|
| D1 | Find and verify 15–20 sources from 2021 onwards (papers, industry reports, standards) | C finds, Y checks |
| D2 | Zotero library with APA 7 formatting | Y |
| D3 | Comparison matrix of existing IDS solutions (strengths, limits, gaps) | C, Y |
| D4 | Standards and compliance notes (Privacy Act, NDB, Essential Eight, ISO 27001, NIST CSF 2.0, ACS Code) | C, K |

## E. Written deliverables
| # | Deliverable | Type | Length | Due |
|---|---|---|---|---|
| E1 | **A1 Project Brief** | Group | 1500 words | Sun 18 Oct |
| E2 | **A2.1 Requirements + Literature Review** (you) | Individual | part of 3300 | Sun 1 Nov |
| E3 | **A2.1** (each member writes their own) | Individual | | Sun 1 Nov |
| E4 | **A2.2 Design + Implementation Plan + Data Collection** (each) | Individual | part of 3300 | Sun 15 Nov |
| E5 | **A2.3 Implementation + Analysis + Results** (each) | Individual | part of 3300 | Sun 29 Nov |
| E6 | **A3 Slides** + speaker notes + demo | Group | 15 min | Week 11 |
| E7 | **A3 Rehearsals** (at least 3 full run-throughs, timed) | Y, K | | Week 10–11 |
| E8 | **A4 Final Report** | Group | 3500 words | Fri 18 Dec |

Note: A2 reports must be **written separately** by each of you, in your own words, from your own role's perspective.

## Totals
- **Written deliverables:** 6 submissions from you (A1, A2.1, A2.2, A2.3, A3, A4), about 8,300+ words of your own plus shared group writing
- **Build:** 20 work items across data, ML, security lab, API, dashboard, cloud and testing
- **Diagrams/artefacts:** 10
- **Meetings:** about 11 weekly meetings with minutes
- **Cost:** $0
