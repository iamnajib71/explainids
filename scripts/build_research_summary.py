"""Condense the research experiments into web/data/research.json for the console's Findings view.

Usage: python scripts/build_research_summary.py [--results docs/results] [--out web/data/research.json]

Reads the JSON written by cross_dataset_eval.py (RQ1), shap_stability_eval.py (RQ2) and
unseen_attack_eval.py (RQ3). A missing experiment becomes null and the console shows it as pending,
so the page never displays a number that no script produced.
"""
import argparse
import json
from pathlib import Path

import numpy as np

SHORT = {"cicids2017": "2017", "csecicids2018": "2018"}
SOURCES = [
    ("Cantone et al., 2024", "https://doi.org/10.1109/ACCESS.2024.3472907"),
    ("D'hooge et al., 2022", "https://doi.org/10.1007/978-3-031-09484-2_2"),
    ("Liu et al., 2022", "https://doi.org/10.1109/CNS56114.2022.9947235"),
    ("Lin & Wang, 2025", "https://doi.org/10.3390/risks13120238"),
    ("Sarhan et al., 2023", "https://doi.org/10.1007/s10207-023-00676-0"),
    ("Lundberg et al., 2020", "https://doi.org/10.1038/s42256-019-0138-9"),
    ("MITRE ATT&CK", "https://attack.mitre.org/"),
]


def load(path: Path) -> dict | None:
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None


def transfer(res: dict | None) -> dict | None:
    if not res:
        return None
    runs = {(r["source"], r["target"]): r for r in res["runs"]["all"]}
    names = [d["name"] for d in res["datasets"]]
    same = [runs[(t, t)]["classifier"]["recall"] for t in names]
    other = [runs[(next(s for s in names if s != t), t)]["classifier"]["recall"] for t in names]
    worst = min(range(len(names)), key=lambda i: other[i])
    src = next(s for s in names if s != names[worst])
    f1 = {f"{SHORT[s]}→{SHORT[t]}": round(r["macro_common"]["f1"], 3) for (s, t), r in runs.items()}
    return {
        "question": "Does it work on a new network?",
        "headline": f"{other[worst]:.0%}", "label": f"of attack flows caught after moving {SHORT[src]} → {SHORT[names[worst]]}",
        "targets": [SHORT[t] for t in names], "same": same, "other": other,
        "tip": (f"Trained on one corrected CIC dataset, tested on the other (LGBM, all {len(res['features']['all'])} shared "
                f"features). Bars show attack recall; macro F1 over the {len(res['common_classes'])} common classes: "
                + ", ".join(f"{k} {v:.2f}" for k, v in f1.items())
                + ". Dropping environment-specific features (port, TCP windows) did not help. Source: docs/results/cross_dataset.md"),
    }


def unseen(res: dict | None, log_res: dict | None) -> dict | None:
    if not res:
        return None
    rows = sorted(res["results"], key=lambda r: -r["unseen"]["either"])
    med = float(np.median([r["unseen"]["either"] for r in rows]))
    tip = (f"Each attack class removed from training in turn ({res['dataset']}, {len(rows)} classes); bars show how much "
           "of it still raised an alert. Isolation Forest threshold set for 1% false alarms on validation benign traffic.")
    if log_res:
        log_med = float(np.median([r["unseen"]["either"] for r in log_res["results"]]))
        tip += f" With signed-log features for the Isolation Forest the median is {log_med:.0%}."
    return {"question": "Can it catch attacks it never saw?", "headline": f"{med:.0%}",
            "label": "median detection of an unseen attack type",
            "classes": [{"class": r["class"], "either": r["unseen"]["either"], "classifier": r["unseen"]["classifier"]}
                        for r in rows],
            "tip": tip + f" Source: docs/results/unseen_{res['dataset']}.md"}


def stability(res: dict | None) -> dict | None:
    if not res or res["local"]["overall"]["median"] is None:
        return None
    per = res["local"]["per_predicted_class"]
    classes = sorted(({"class": c, "median": v["median"]} for c, v in per.items() if v["count"] and c != "BENIGN"),
                     key=lambda x: -x["median"])
    skipped, total = res["local"]["skipped_prediction_changes"], res["local"]["total_pairs"]
    return {"question": "Do explanations stay the same?", "headline": f"{res['local']['overall']['median']:.2f}",
            "label": f"median top-{res['k']} SHAP overlap across {len(res['seeds'])} training seeds",
            "classes": classes,
            "tip": (f"Same {res['explained_flows']} test attack flows explained by models trained with different seeds; "
                    f"overlap 1 = identical top-{res['k']} features, 0 = none shared. {skipped:,} of {total:,} flow pairs "
                    f"skipped because the prediction changed. Source: docs/results/shap_stability_{res['dataset']}.md")}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="docs/results")
    ap.add_argument("--dataset", default="cicids2017", help="dataset shown for RQ2 and RQ3")
    ap.add_argument("--out", default="web/data/research.json")
    args = ap.parse_args()
    r = Path(args.results)
    out = {"transfer": transfer(load(r / "cross_dataset.json")),
           "stability": stability(load(r / f"shap_stability_{args.dataset}.json")),
           "unseen": unseen(load(r / f"unseen_{args.dataset}.json"), load(r / f"unseen_{args.dataset}_log.json")),
           "sources": [{"label": label, "url": url} for label, url in SOURCES]}
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    print(f"wrote {args.out}: " + ", ".join(f"{k}={'ok' if v else 'pending'}" for k, v in out.items() if k != "sources"))


if __name__ == "__main__":
    main()
