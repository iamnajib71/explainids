# Matched target-only controls and benign-service regression

## Scope and scientific boundary

Extend `scripts/multi_env_eval.py` without changing the saved deployed detector. Existing results remain historical; new matched-control runs must use a new output filename. This is evaluation infrastructure, not a claim of improved detection. No new traffic, paid service or unrestricted training run is required to implement it.

The existing small-label selection is an **oracle class-balanced sample from each class's earlier training partition**, not the first incidents in a chronological stream. Test partitions remain full and chronological per class; this is not a globally ordered/session-independent deployment study.

## Optional matched control

`--target-only` opts into paired source-plus-target and target-only conditions for every direction, label budget and sampling seed. Draw the local sample once using the existing `few_shot` policy. Both conditions consume the exact same target rows and identical model hyperparameters; target-only has no source observations for fitting or calibration.

The `--local-benign` count is a **total target benign annotation budget**, not an additional calibration allowance. In matched mode reserve `ceil(n * --calibration-fraction)` of the sampled benign rows, ordered by timestamp, for threshold calibration; default fraction0.2. At least one benign fitting row and one calibration row are required. Neither the classifier nor the anomaly model may fit the reserved rows. Both paired conditions use only this identical reserved target-benign set for anomaly threshold selection; neither consumes source validation nor any extra target validation labels. Matched mode therefore changes the few-shot condition's calibration policy relative to historical runs; label it `few-shot matched` and document the difference. Preserve legacy few-shot behavior when the flag is absent.

Retain original processed-row indexes through training capping so provenance can audit partition membership. Record namespaced sample/fitting/calibration identity hashes, actual per-class sampled counts, source training count, target fitting/calibration counts, and zero extra validation observations in matched rows. Source-only/pooled/legacy rows disclose all validation rows inspected and benign rows used. No target-only improvement is credited to transfer without this comparison.

## Metrics and benign evaluation

`--benign-eval CSV [CSV ...]` optionally scores every fitted condition on separate labelled all-benign CSVs. Reject any file missing a label column or containing non-benign labels. Each input gets a distinct named result; do not merge profiles or silently exclude inconvenient model outputs. These currently inspected captures are development regression data, not an untouched final environment. Existing `--lab` remains supported.

Every test result includes binary precision/recall/F1, FPR and confusion counts for classifier-only, anomaly-only and their OR rule; full multiclass precision/recall/F1/support, observed/common macro metrics, labelled confusion matrix; flow counts and invalid-row counts. Keep compact historical fields and class-balanced detection for comparison, but distinguish detection from class attribution and retain unknown-class rows. Missing required features fail; invalid numeric observations are counted and excluded consistently. Reject an empty remaining evaluation set.

All-benign attack recall/F1, no-predicted-alert precision, absent-benign FPR, and absent-attack class-balanced detection are N/A. JSON uses null, never non-standard NaN/Infinity (`allow_nan=False`). Markdown renders N/A. Full per-seed/class metrics and confusion matrices must accompany summary tables; a highlighted macro or binary score alone is insufficient.

## Acceptance checks

1. Matching target identity hashes and calibration frames in each pair; zero source fitting/calibration rows in target-only.
2. Fitting, calibration and later target-test indexes are disjoint; calibration is counted within the declared benign budget. Reject overlapping/invalid partitions or an insufficient benign budget.
3. Per-class support and metrics agree with labelled confusion totals, including unknown labels; classifier and anomaly detection remain distinct.
4. All-benign outputs serialize strictly with null attack metrics and correct false-alert counts.
5. A small synthetic CLI integration covers opt-in matching, multiple benign CSVs, metadata and Markdown/JSON rendering without fitting a large model or asserting real-world performance.

## Deferred study work

Global temporal/session grouping, independent environment collection, non-oracle chronological annotation, analyst incident burden and publication conclusions require separate prespecified experiments. This patch does not implement or claim them. Matched row budgets count observations rather than independent incidents; hashes identify selection, not the cost of obtaining ground truth.
