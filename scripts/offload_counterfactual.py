"""Are real-network false alerts an artefact of where the sensor sits? A paired counterfactual.

  python scripts/offload_counterfactual.py data/sensor/<session> [...] --results docs/results/offload_counterfactual.md

For each captured session: rewrite the capture with segmentation offload undone
(`resegment_pcap.py`), run the same extractor and validation, and score both versions with the same
frozen detector. Only the packetisation differs, so any change in verdict is caused by the capture
artefact, not by the traffic. Flows are paired across the two versions by (endpoints, destination port,
protocol, start time); keys are used in memory only and never written. Outputs are aggregates.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))
from ids import sensor  # noqa: E402
from ids.data import BENIGN  # noqa: E402
from ids.evaluate import wilson_interval  # noqa: E402
from ids.scoring import align_columns  # noqa: E402
from resegment_pcap import resegment  # noqa: E402
from wsl_convert import convert  # noqa: E402

KEY = ["Src IP", "Dst IP", "Dst Port", "Protocol", "Timestamp"]


def verdicts(det, csv: Path) -> pd.DataFrame:
    raw = pd.read_csv(csv, low_memory=False)
    aligned, missing = align_columns(raw, det.features)
    if missing:
        raise ValueError(f"{csv}: {len(missing)} features missing")
    X = aligned[det.features].apply(pd.to_numeric, errors="coerce")
    pred = det.predict(X)
    outlier = det.anomaly(X)[1]
    return pd.DataFrame({**{k: aligned[k].astype(str).to_numpy() for k in KEY},
                         "classifier": pred != BENIGN, "anomaly_only": (pred == BENIGN) & outlier,
                         "alert": (pred != BENIGN) | outlier,
                         "super_packet": (X["Packet Length Max"] > 1500).to_numpy(),
                         "packets": (X["Total Fwd Packet"] + X["Total Bwd packets"]).to_numpy()})


def counts(v: pd.DataFrame) -> dict:
    return {"flows": int(len(v)), "alerts": int(v["alert"].sum()), "classifier_alerts": int(v["classifier"].sum()),
            "anomaly_only_alerts": int(v["anomaly_only"].sum()), "flows_with_super_packets": int(v["super_packet"].sum()),
            "alert_rate": float(v["alert"].mean()) if len(v) else None,
            "alert_rate_ci": list(wilson_interval(int(v["alert"].sum()), len(v)))}


def paired(orig: pd.DataFrame, reseg: pd.DataFrame) -> dict:
    """Pair flows whose key is unique in both versions."""
    o = orig[~orig.duplicated(KEY, keep=False)].set_index(KEY)
    r = reseg[~reseg.duplicated(KEY, keep=False)].set_index(KEY)
    both = o.add_suffix("_o").join(r.add_suffix("_r"), how="inner")
    sp = both["super_packet_o"]
    return {"pairs": int(len(both)),
            "alert_to_clear": int((both["alert_o"] & ~both["alert_r"]).sum()),
            "clear_to_alert": int((~both["alert_o"] & both["alert_r"]).sum()),
            "alert_both": int((both["alert_o"] & both["alert_r"]).sum()),
            "super_packet_pairs": int(sp.sum()),
            "alert_to_clear_super": int((both["alert_o"] & ~both["alert_r"] & sp).sum()),
            "alert_to_clear_normal": int((both["alert_o"] & ~both["alert_r"] & ~sp).sum()),
            "alerts_on_super_original": int((both["alert_o"] & sp).sum()),
            "alerts_on_normal_original": int((both["alert_o"] & ~sp).sum())}


def run_session(session: Path, det, features: list[str], distro: str, spacing_us: int = 1) -> dict:
    out = session / f"resegmented_{spacing_us}us"
    if out.exists():                      # derived by this script only; rebuilt so reruns are clean
        shutil.rmtree(out)
    out.mkdir()
    pcap = out / "capture_resegmented.pcap"
    stats = resegment(session / "capture.pcap", pcap, spacing_us=spacing_us)
    produced = convert(pcap, out / "converted", distro, timeout=1800, log=out / "converter.log")
    kept, dropped = sensor.validate_csv(produced, out / "validated.csv", features)
    orig, reseg = verdicts(det, session / "validated.csv"), verdicts(det, out / "validated.csv")
    return {"session": session.name[:12], "resegment": stats, "dropped_unusable": dropped,
            "original": counts(orig), "resegmented": counts(reseg), "paired": paired(orig, reseg)}


def to_markdown(res: dict) -> str:
    md = ["# Offload counterfactual: same traffic, wire-sized packets", "",
          f"Generated on {res['generated']}. Frozen detector {res['model']}. Each capture is rewritten with "
          f"segmentation offload undone (pieces {res['spacing_us']} µs apart) and re-extracted; both versions are scored by the same model. Alerts "
          "are on unlabelled traffic from networks in ordinary use, so they are candidate false alerts.", "",
          "| Session | Packets split | Flows (orig → reseg) | Alerts orig | Alerts reseg | Anomaly-only orig → reseg | "
          "Paired flows | Alert → clear | Clear → alert |", "|---|---:|---|---:|---:|---|---:|---:|---:|"]
    for s in res["sessions"]:
        o, r, p = s["original"], s["resegmented"], s["paired"]
        md.append(f"| {s['session']} | {s['resegment']['split']:,} | {o['flows']} → {r['flows']} | "
                  f"{o['alerts']} ({o['alert_rate']:.1%}) | {r['alerts']} ({r['alert_rate']:.1%}) | "
                  f"{o['anomaly_only_alerts']} → {r['anomaly_only_alerts']} | {p['pairs']} | "
                  f"{p['alert_to_clear']} | {p['clear_to_alert']} |")
    t = res["totals"]
    md += ["", "## Pooled", "", "| Measure | Value |", "|---|---|",
           f"| Alerts, original capture | {t['alerts_o']} / {t['flows_o']} ({t['rate_o']:.1%}, 95% CI "
           f"{t['ci_o'][0]:.1%}–{t['ci_o'][1]:.1%}) |",
           f"| Alerts, offload undone | {t['alerts_r']} / {t['flows_r']} ({t['rate_r']:.1%}, 95% CI "
           f"{t['ci_r'][0]:.1%}–{t['ci_r'][1]:.1%}) |",
           f"| Paired alerts that clear when offload is undone | {t['a2c']} of {t['alert_pairs']} |",
           f"| … of which on flows that contained super-packets | {t['a2c_super']} |",
           f"| Paired flows that newly alert | {t['c2a']} of {t['pairs']} |",
           f"| Exact McNemar test (alert→clear vs clear→alert) | p = {t['mcnemar_p']:.2g} |",
           "", "Accuracy is not reported (rule 4). No addresses or per-flow records are stored in this file.", "",
           f"Total run time {res['minutes']:.1f} min."]
    return "\n".join(md) + "\n"


def main() -> None:
    from scipy.stats import binomtest
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("sessions", nargs="+", type=Path)
    ap.add_argument("--model-dir", type=Path, default=ROOT / "models")
    ap.add_argument("--distro", default="Ubuntu-24.04")
    ap.add_argument("--spacing-us", type=int, default=1, help="gap between the pieces of a split segment")
    ap.add_argument("--results", default="docs/results/offload_counterfactual.md")
    args = ap.parse_args()
    t0 = time.perf_counter()
    det = joblib.load(args.model_dir / "detector.joblib")
    features = sensor.load_features(args.model_dir / "model_card.json")
    sessions = []
    for s in args.sessions:
        r = run_session(s, det, features, args.distro, args.spacing_us)
        sessions.append(r)
        print(json.dumps({k: r[k] for k in ("session", "original", "resegmented", "paired")}), flush=True)
    fo = sum(s["original"]["flows"] for s in sessions)
    fr = sum(s["resegmented"]["flows"] for s in sessions)
    ao = sum(s["original"]["alerts"] for s in sessions)
    ar = sum(s["resegmented"]["alerts"] for s in sessions)
    a2c = sum(s["paired"]["alert_to_clear"] for s in sessions)
    c2a = sum(s["paired"]["clear_to_alert"] for s in sessions)
    totals = {"flows_o": fo, "flows_r": fr, "alerts_o": ao, "alerts_r": ar, "rate_o": ao / fo, "rate_r": ar / fr,
              "ci_o": list(wilson_interval(ao, fo)), "ci_r": list(wilson_interval(ar, fr)),
              "pairs": sum(s["paired"]["pairs"] for s in sessions), "a2c": a2c, "c2a": c2a,
              "alert_pairs": sum(s["paired"]["alert_to_clear"] + s["paired"]["alert_both"] for s in sessions),
              "a2c_super": sum(s["paired"]["alert_to_clear_super"] for s in sessions),
              "mcnemar_p": binomtest(a2c, a2c + c2a, 0.5).pvalue if a2c + c2a else float("nan")}
    card = json.loads((args.model_dir / "model_card.json").read_text(encoding="utf-8"))
    res = {"generated": time.strftime("%Y-%m-%d"), "spacing_us": args.spacing_us, "model": f"{det.name.upper()} trained on {card.get('dataset')}",
           "sessions": sessions, "totals": totals, "minutes": (time.perf_counter() - t0) / 60}
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(to_markdown(res), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps(res, indent=1, default=float), encoding="utf-8")
    print(f"results in {out}")


if __name__ == "__main__":
    main()
