"""Does the local model of normal hide attacks the detector has never seen? Leave-one-class-out under deployment.

Usage:
  python scripts/unseen_veto_eval.py data/processed/cicids2017.parquet data/processed/csecicids2018.parquet \
      --fit-sessions $(cat data/study_sessions.txt) --study data/sensor/study_wifi_20261101.json \
      [--portable] --results docs/results/unseen_veto.md

`attack_retention_eval.py` found that, for every attack class the model was trained on, the classifier makes
every detection and the anomaly layer adds none, so a veto on anomaly alerts cannot cost known-attack detection.
The anomaly layer exists for attacks never seen in training (RQ3). This script asks whether the site's local
model of normal vetoes those.

For each attack class C: C is removed from the source training data and from the k labelled target flows; the
deployment recipe is then built as usual (few-shot model, 30 triaged local flows from the earlier evening) and
scored on every flow of C in the source and target test splits. Variants: the repaired model with the benchmark
anomaly layer, with the exemplar envelope, and with the local anomaly threshold, all fitted on the earlier
evening; the real-network false-alert rate on the later evening is reported beside them.

Decision rule, fixed before the first run: the envelope *costs novel-attack detection* if, pooled over classes
and both test splits, it removes more than 10% of the unseen-attack flows that the benchmark anomaly layer alone
catches. Per-class counts are reported so a loss concentrated in one class is visible. One seed (42): each class
needs its own retraining. Outputs hold aggregates only; accuracy is never reported (rule 4).
"""
from __future__ import annotations

import argparse
import copy
import json
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
from real_network_eval import load_session, score_blocks, study_sessions  # noqa: E402
from service_aware_eval import ENV_SPECIFIC, fit_detector, few_shot, load_dataset  # noqa: E402

from ids import SEED  # noqa: E402
from ids.data import BENIGN, LABEL_COL, feature_columns  # noqa: E402
from ids.envelope import ExemplarEnvelope  # noqa: E402
from ids.repair import triage_sample  # noqa: E402

MIN_FLOWS = 10


def without(split: dict, cls: str) -> dict:
    """A dataset dict with one attack class removed from every split."""
    return {k: (v[v[LABEL_COL] != cls] if isinstance(v, pd.DataFrame) else v) for k, v in split.items()}


def layers(det, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Per flow: caught by the classifier, and caught by the anomaly layer."""
    return np.asarray(det.predict(X) != BENIGN), np.asarray(det.anomaly(X)[1])


def veto_counts(base, variant, X: pd.DataFrame) -> dict:
    """How the variant's anomaly rule changes what the benchmark anomaly layer alone catches on X."""
    clf, anom = layers(base, X)
    _, anom_v = layers(variant, X)
    only = anom & ~clf
    return {"flows": int(len(X)), "classifier": int(clf.sum()), "anomaly_only": int(only.sum()),
            "vetoed": int((only & ~anom_v).sum()), "caught": int((clf | anom).sum()),
            "caught_variant": int((clf | anom_v).sum())}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("source")
    ap.add_argument("target")
    ap.add_argument("--fit-sessions", nargs="+", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model", default="lgbm")
    ap.add_argument("--cap", type=int, default=60000)
    ap.add_argument("--k", type=int, default=50)
    ap.add_argument("--service-flows", type=int, default=30)
    ap.add_argument("--portable", action="store_true")
    ap.add_argument("--seed", type=int, default=SEED, help="label, triage and model seed (confirmation runs use 1-4)")
    ap.add_argument("--results", default="docs/results/unseen_veto.md")
    args = ap.parse_args()

    t0 = time.perf_counter()
    src, tgt = load_dataset(args.source, args.cap), load_dataset(args.target, args.cap)
    feats = [f for f in feature_columns(src["test"]) if f in set(feature_columns(tgt["test"]))]
    if args.portable:
        feats = [f for f in feats if f not in ENV_SPECIFIC]
    fit_pool = pd.concat([load_session(Path(s), feats) for s in args.fit_sessions], ignore_index=True)
    blocks = [b for b in (load_session(p, feats) for p in study_sessions(args.study)) if len(b)]
    tests = {src["name"]: src["test"], tgt["name"]: tgt["test"]}
    classes = sorted({c for t in tests.values() for c, n in t[LABEL_COL].value_counts().items()
                      if c != BENIGN and n >= MIN_FLOWS})
    rows = []
    for cls in classes:
        s, t = without(src, cls), without(tgt, cls)
        labels = few_shot(t, args.k, 1000, args.seed)
        base = fit_detector(pd.concat([s["train"], labels]), s["val"], feats, args.model)
        triaged, _ = triage_sample(base, fit_pool, feats, args.service_flows, args.seed)
        rep = fit_detector(pd.concat([s["train"], labels, triaged]), s["val"], feats, args.model)
        thr = copy.deepcopy(rep)
        thr.tune_anomaly_threshold(fit_pool[feats])
        variants = {"exemplar envelope": ExemplarEnvelope(rep, fit_pool[feats]), "local anomaly threshold": thr}
        row = {"class": cls, "real_network_rate": {"benchmark anomaly layer": score_blocks(rep, blocks, feats)["rate"],
                                                   **{v: score_blocks(d, blocks, feats)["rate"] for v, d in variants.items()}},
               "splits": {}}
        for name, test in tests.items():
            X = test[test[LABEL_COL] == cls][feats]
            if len(X) >= MIN_FLOWS:
                row["splits"][name] = {v: veto_counts(rep, d, X) for v, d in variants.items()}
        rows.append(row)
        print(cls, json.dumps({n: {v: (c["anomaly_only"], c["vetoed"]) for v, c in d.items()}
                               for n, d in row["splits"].items()}), flush=True)

    res = {"generated": time.strftime("%Y-%m-%d"), "model": args.model, "features": len(feats),
           "portable": args.portable, "k": args.k, "service_flows": args.service_flows, "seed": args.seed,
           "fit_pool_flows": int(len(fit_pool)), "eval_flows": int(sum(len(b) for b in blocks)),
           "rows": rows, "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(f"results in {out}")


def to_markdown(res: dict) -> str:
    feats = "without port and TCP-window features" if res["portable"] else "all features"
    L = ["# Does the local model of normal hide unseen attacks?", "",
         f"Generated on {res['generated']}. {res['model'].upper()}, {res['features']} features ({feats}), k = {res['k']}, "
         f"{res['service_flows']} triaged local flows, seed {res['seed']}. Each attack class is left out of all training "
         f"in turn; local model of normal fitted on {res['fit_pool_flows']:,} flows of an earlier evening. "
         "*Anomaly only*: unseen flows that only the benchmark anomaly layer catches. *Vetoed*: of those, how many the "
         "local rule removes.", "",
         "| Unseen class | Test split | Flows | Classifier catches | Anomaly only | Vetoed by exemplar envelope | "
         "Vetoed by local threshold |", "|---|---|---|---|---|---|---|"]
    total = {"exemplar envelope": [0, 0], "local anomaly threshold": [0, 0]}
    for r in res["rows"]:
        for split, d in r["splits"].items():
            e, t = d["exemplar envelope"], d["local anomaly threshold"]
            L.append(f"| {r['class']} | {split} | {e['flows']:,} | {e['classifier'] / e['flows']:.1%} | "
                     f"{e['anomaly_only']:,} ({e['anomaly_only'] / e['flows']:.1%}) | {e['vetoed']:,} | {t['vetoed']:,} |")
            for v in total:
                total[v][0] += d[v]["anomaly_only"]
                total[v][1] += d[v]["vetoed"]
    L.append("")
    for v, (only, vetoed) in total.items():
        share = vetoed / only if only else 0.0
        L.append(f"**{v.capitalize()}:** removes {vetoed:,} of {only:,} anomaly-only unseen detections ({share:.1%}); "
                 + ("costs novel-attack detection (rule: more than 10%)." if share > 0.10 else
                    "within the 10% rule."))
        L.append("")
    rates = {v: np.mean([r["real_network_rate"][v] for r in res["rows"]]) for v in res["rows"][0]["real_network_rate"]}
    L += ["Real-network false-alert rate on the later evening, mean over the leave-one-out models: "
          + "; ".join(f"{v} {x:.1%}" for v, x in rates.items()) + ".", "",
          "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
          f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
