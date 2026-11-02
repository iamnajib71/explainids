"""End-to-end acceptance check of the deployment repair loop, through the real API.

  python scripts/repair_loop_check.py data/processed/cicids2017.parquet \
      --day1 $(cat data/study_sessions.txt) --day2 $(cat data/study_sessions_day2.txt) \
      --lab-runs data/lab/run_20261025T050509Z data/lab/run_20261025T050628Z data/lab/run_20261025T051149Z \
      --results docs/results/repair_loop.md

What an operator does, in order, using only the console's API:
  1. Serve the shipped model; stream the second evening through /sensor/ingest (baseline).
  2. Stream the first evening; the analyst dismisses its alerts (the household's traffic, assumed benign as in
     the study) and, by mistake, three lab attack flows submitted through /predict.
  3. Export /triage/repair-set.csv and run scripts/repair_model.py with the first evening as local normal
     traffic. Its gate should hold back the wrongly dismissed attacks.
  4. Serve the repaired model; stream the second evening again (alerts and low-priority counts), score lab
     attacks from the other two replicates (detection kept?), and dismiss three of them: the API should mark
     them not eligible for retraining.
The model is trained on CIC-IDS2017 only (no few-shot labels), so absolute rates differ from the study.
Runs in-process with FastAPI's test client against a temporary triage database; aggregates only.
"""
from __future__ import annotations

import argparse
import io
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))
from attack_retention_eval import load_lab_run  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

import api.main as api  # noqa: E402
from ids.data import BENIGN, LABEL_COL  # noqa: E402

CHUNK = 1000
WRONG = 3


def serve(model_dir: Path, triage_db: Path) -> TestClient:
    """Point the API at a model folder with fresh in-memory state and a given triage database."""
    api.MODEL_DIR, api.TRIAGE_DB, api.API_KEY = model_dir, triage_db, None
    api._state.clear()
    api._state["alerts"] = []
    api._alert_features.clear()
    api._sensor.update(rows=[], alerts=[], seq=0, batches=[], summary=None)
    client = TestClient(api.app)
    api.state()
    return client


def stream(client: TestClient, sessions: list[Path], tag: str) -> dict:
    """Send each session's validated flows to /sensor/ingest in bounded batches; return totals and alert ids."""
    alert_ids: list[str] = []
    for s in sessions:
        frame = pd.read_csv(s / "validated.csv", low_memory=False)
        for start in range(0, len(frame), CHUNK):
            part = frame.iloc[start:start + CHUNK]
            r = client.post("/sensor/ingest", data={"sensor_session": f"{tag}-{s.name[:8]}",
                                                   "batch_id": f"{tag}-{s.name[:8]}-{start}"},
                            files={"file": ("flows.csv", part.to_csv(index=False).encode(), "text/csv")})
            if r.status_code != 200:
                raise SystemExit(f"ingest failed for {s.name}: {r.status_code} {r.text[:200]}")
    summary = api._sensor["summary"]
    alert_ids = [a["alert_id"] for a in api._state["alerts"] if a.get("sensor_session", "").startswith(tag)]
    return {"flows": summary["total_flows"], "alerts": summary["total_alerts"],
            "alert_rate": summary["total_alerts"] / summary["total_flows"], "low_priority": summary.get("demoted", 0),
            "alert_ids": alert_ids}


def submit_attacks(client: TestClient, attacks: pd.DataFrame) -> tuple[list[str], float]:
    """Score lab attack flows through /predict; return the alert ids raised and the share caught."""
    feats = api.detector().features
    ids: list[str] = []
    for start in range(0, len(attacks), CHUNK):
        flows = attacks[feats].iloc[start:start + CHUNK].to_dict("records")
        ids += [a["alert_id"] for a in client.post("/predict", json={"flows": flows}).json()["alerts"]]
    return ids, len(ids) / len(attacks)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parquet")
    ap.add_argument("--model-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--day1", nargs="+", type=Path, required=True)
    ap.add_argument("--day2", nargs="+", type=Path, required=True)
    ap.add_argument("--lab-runs", nargs=3, type=Path, required=True)
    ap.add_argument("--results", type=Path, default=ROOT / "docs/results/repair_loop.md")
    args = ap.parse_args()
    t0 = time.perf_counter()
    work = Path(tempfile.mkdtemp(prefix="repair_loop_"))
    db = work / "triage.sqlite"
    out: dict = {"generated": time.strftime("%Y-%m-%d")}

    client = serve(args.model_dir, db)                                               # 1. baseline
    feats = api.detector().features
    lab = pd.concat([load_lab_run(p, feats) for p in args.lab_runs], ignore_index=True)
    attack = lab[LABEL_COL] != BENIGN
    poison = lab[attack & (lab["replicate"] == args.lab_runs[0].name)]
    held = lab[attack & (lab["replicate"] != args.lab_runs[0].name)]
    base2 = stream(client, args.day2, "day2")
    _, base_recall = submit_attacks(client, held)
    out["shipped"] = {"day2": {k: v for k, v in base2.items() if k != "alert_ids"}, "lab_recall": base_recall}

    client = serve(args.model_dir, db)                                               # 2. triage on day 1
    day1 = stream(client, args.day1, "day1")
    for aid in day1["alert_ids"]:
        client.post(f"/alerts/{aid}/status", params={"status": "dismissed"})
    poison_ids, _ = submit_attacks(client, poison)
    wrong = poison_ids[:WRONG]
    wrong_features = pd.DataFrame([api._alert_features[aid] for aid in wrong])
    verdicts = [client.post(f"/alerts/{aid}/status", params={"status": "dismissed"}).json()["repair_eligible"]
                for aid in wrong]
    out["triage"] = {"day1": {k: v for k, v in day1.items() if k != "alert_ids"},
                     "dismissed_household": len(day1["alert_ids"]), "dismissed_attacks": len(wrong),
                     "eligibility_at_decision": verdicts, "summary": client.get("/triage/summary").json()}

    repair_csv = work / "repair_set.csv"                                             # 3. repair
    repair_csv.write_bytes(client.get("/triage/repair-set.csv").content)
    repaired_dir = work / "models_repaired"
    subprocess.run([sys.executable, str(ROOT / "scripts/repair_model.py"), args.parquet, "--model-dir",
                    str(args.model_dir), "--repair-set", str(repair_csv), "--local-sessions",
                    *map(str, args.day1), "--outdir", str(repaired_dir)], check=True, cwd=ROOT)
    card = json.loads((repaired_dir / "model_card.json").read_text(encoding="utf-8"))["repair"]
    out["repair"] = {k: card[k] for k in ("repair_flows", "repair_flows_held_back", "local_normal_flows")}
    out["repair"]["benchmark"] = {when: {k: card[when][k] for k in ("macro_f1", "attack_recall", "benign_fpr")}
                                  for when in ("before", "after")}

    client = serve(repaired_dir, work / "triage_after.sqlite")                       # 4. repaired model
    inside = api.detector().resembles_site_normal(wrong_features)
    out["repair"]["wrong_dismissals_inside_envelope"] = int(np.sum(inside))
    rep2 = stream(client, args.day2, "day2")
    held_ids, rep_recall = submit_attacks(client, held)
    after = [client.post(f"/alerts/{aid}/status", params={"status": "dismissed"}).json()["repair_eligible"]
             for aid in held_ids[:WRONG]]
    out["repaired"] = {"day2": {k: v for k, v in rep2.items() if k != "alert_ids"}, "lab_recall": rep_recall,
                       "wrong_dismissals_eligible": after}
    out["lab"] = {"poison_attacks": int(len(poison)), "held_out_attacks": int(len(held))}
    out["minutes"] = (time.perf_counter() - t0) / 60

    args.results.parent.mkdir(parents=True, exist_ok=True)
    args.results.with_suffix(".json").write_text(json.dumps(out, indent=1, default=float), encoding="utf-8")
    args.results.write_text(to_markdown(out), encoding="utf-8")
    print(to_markdown(out))


def to_markdown(o: dict) -> str:
    s, t, r, p = o["shipped"], o["triage"], o["repair"], o["repaired"]
    fmt = lambda v: "unchecked (no site envelope)" if v is None else ("eligible" if v else "held back")  # noqa: E731
    return "\n".join([
        "# Repair loop, end to end through the API", "",
        f"Generated on {o['generated']} by `scripts/repair_loop_check.py`. Shipped model: CIC-IDS2017 only. "
        "Every step uses the console's own API in-process; the household's traffic is assumed benign, as in the study.", "",
        "| Step | Measure | Result |", "|---|---|---|",
        f"| Shipped model, second evening | alerts / flows | {s['day2']['alerts']:,} / {s['day2']['flows']:,} ({s['day2']['alert_rate']:.1%}) |",
        f"| Shipped model | lab attacks caught (other replicates) | {s['lab_recall']:.1%} of {o['lab']['held_out_attacks']} |",
        f"| Triage, first evening | household alerts dismissed | {t['dismissed_household']:,} |",
        f"| Triage | lab attacks dismissed by mistake | {t['dismissed_attacks']}; at decision time: "
        + ", ".join(fmt(v) for v in t["eligibility_at_decision"]) + " |",
        f"| Repair (`repair_model.py`) | dismissals used / held back by the gate | {r['repair_flows']:,} / {r['repair_flows_held_back']:,} |",
        f"| Repair | wrongly dismissed attacks that passed the gate | {r['wrong_dismissals_inside_envelope']} of {t['dismissed_attacks']} |",
        f"| Repair | local normal flows in the site envelope | {r['local_normal_flows']:,} |",
        f"| Repair | benchmark macro F1 / attack recall / benign FPR, before → after | "
        f"{r['benchmark']['before']['macro_f1']:.3f} → {r['benchmark']['after']['macro_f1']:.3f} / "
        f"{r['benchmark']['before']['attack_recall']:.4f} → {r['benchmark']['after']['attack_recall']:.4f} / "
        f"{r['benchmark']['before']['benign_fpr']:.2%} → {r['benchmark']['after']['benign_fpr']:.2%} |",
        f"| Repaired model, second evening | alerts / flows | {p['day2']['alerts']:,} / {p['day2']['flows']:,} ({p['day2']['alert_rate']:.1%}) |",
        f"| Repaired model | low-priority (vetoed, kept) | {p['day2']['low_priority']:,} |",
        f"| Repaired model | lab attacks caught (other replicates) | {p['lab_recall']:.1%} |",
        f"| Repaired model | wrong dismissals of caught attacks | " + ", ".join(fmt(v) for v in p["wrong_dismissals_eligible"]) + " |",
        "", "Accuracy is not reported (rule 4). No addresses or per-flow records.", "",
        f"Total run time {o['minutes']:.1f} min."]) + "\n"


if __name__ == "__main__":
    main()
