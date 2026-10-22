# AGENTS.md — shared instructions for Codex CLI and Claude Code

## Project
**AI-Based Cybersecurity Intrusion Detection and Threat Analysis Dashboard + Cloud**
University group project, team of 3: Project Lead and Data & ML Lead; Security & Cloud Lead; Research & Platform Lead. Member names, student IDs and the name-to-role mapping are in `private/TEAM.md` (local only, gitignored).
Goal: HD grade in every assessment at **$0 cost**.

Read these first:
- `docs/PROJECT_PLAN.md`: scope, architecture, timeline
- `docs/WORK_BREAKDOWN.md`: task list and owners
- `assessments/`: briefs and marking rubrics (the source of truth for what gets marked)

## Repository layout
```
assessments/   assessment briefs + rubrics (read-only reference)
docs/          plan, specs, design decisions, diagrams (docs/diagrams/)
reports/       report drafts per assessment (A1/, A2/, A3/, A4/)
meetings/      meeting minutes + leadership log (evidence for marking)
evidence/      screenshots and artefacts proving work done
data/          datasets: NEVER committed (raw/, processed/, lab/)
notebooks/     exploratory analysis
src/ids/       Python package: data pipeline, models, explainability, threat mapping
api/           FastAPI service
dashboard/     Streamlit dashboard
infra/         Docker, Azure deployment scripts
tests/         pytest
```

## Tech stack
Python 3.11, pandas, scikit-learn, XGBoost, LightGBM, imbalanced-learn, SHAP, FastAPI, Streamlit, Plotly, SQLite, Docker, Azure for Students, pytest, GitHub Actions.

## Rules
1. **$0 budget.** No paid APIs or managed ML services. Cloud resources must be the smallest tier and easy to shut down.
2. **Never commit data, models over 50 MB, secrets or `.env` files.**
3. **Reproducibility:** fixed random seeds (`42`); every result in a report must be regenerable from a script or notebook in this repo.
4. **Metrics:** always report precision, recall, F1 (macro and per class), false-positive rate and confusion matrix. Never report accuracy alone (datasets are imbalanced).
5. **Ethics:** attack traffic is generated only inside the isolated VirtualBox host-only lab. No scanning of real networks.
6. **Specs first:** implement modules from specs in `docs/specs/` when present. Keep functions small, typed and tested.
7. **References:** academic citations must be real and verifiable (DOI or URL). Never invent sources. APA 7.
8. **Small commits** with clear messages; work on feature branches.
10. **Public repository: privacy.** The GitHub repo is public. Never commit student names, student IDs, emails, assessment briefs/rubrics, report drafts or submissions, cover sheets or meeting records. These live in gitignored paths (`private/`, `assessments/`, `templates/`, `meetings/`, `reports/A1..A4/`, `reports/course_details.json`). Run `git grep` for names and IDs before every push.
9. **Group assessments (A1, A3, A4) use the ECA Group Assessment Cover Sheet** at `templates/Group_Assessment_Cover_Sheet.docx` (never edit the template). Shared details live in `reports/course_details.json`; per-assessment details and AI acknowledgements live in `reports/<A>/cover_sheet.json`. Build the submission with `python reports/tools/make_submission.py <A>`, which produces `reports/<A>/submission/` (filled cover sheet + report .docx + merged `*_SUBMISSION.pdf`). Declaration checkboxes are the students' sign-off: only they set them to true. A2 is individual and needs the individual cover sheet (not yet provided).
