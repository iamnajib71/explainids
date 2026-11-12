"""Score one or more validated sensor captures and produce traceable, privacy-preserving output.

Usage:
  python scripts/score_capture.py data/sensor/<session> [more sessions...] --label home-wifi \
      --results docs/results/live_home_wifi.md

For every flow the detector's verdict is recorded with its evidence: predicted class, confidence,
anomaly flag, candidate ATT&CK technique and the three SHAP features that pushed it there. Hosts are
replaced by keyed pseudonyms and an internal/external flag; destination port, protocol and capture
time are kept so each alert can be traced back to a service and a moment.

Interpretation. Live captures carry no ground truth. On a network where no attack traffic was
generated, every alert is a *candidate* false alarm that an analyst would have to review; it is not
a confirmed false positive, and absence of alerts is not proof of absence of compromise. The report
therefore states alert burden (alerts, rate with a 95% Wilson interval, alerts per hour), not
precision or recall.

Outputs: per-flow `scored_flows.csv` inside each session folder (private, gitignored) and an aggregate
report at --results that contains no addresses.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ids.data import BENIGN
from ids.evaluate import wilson_interval
from ids.explain import Explainer
from ids.privacy import pseudonymise_value
from ids.threat import context_for

SERVICES = {20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 88: "Kerberos", 123: "NTP", 135: "MS-RPC", 137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS",
            143: "IMAP", 389: "LDAP", 443: "HTTPS", 445: "SMB", 464: "Kerberos-pw", 465: "SMTPS", 587: "SMTP",
            636: "LDAPS", 853: "DNS-over-TLS", 993: "IMAPS", 1900: "SSDP", 3268: "LDAP-GC", 3269: "LDAP-GC-TLS",
            3389: "RDP", 5353: "mDNS", 5355: "LLMNR", 8009: "Cast", 8080: "HTTP-alt", 8443: "HTTPS-alt"}
PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP"}


def service_name(port, protocol) -> str:
    try:
        port = int(port)
    except (TypeError, ValueError):
        return "unknown"
    if port in SERVICES:
        return SERVICES[port]
    if port == 0 and int(protocol) == 1:
        return "ICMP"
    return "ephemeral" if port >= 49152 else f"port-{port}"


def scope(address) -> str:
    """internal / external / multicast, never the address itself."""
    try:
        ip = ipaddress.ip_address(str(address).strip())
    except ValueError:
        return "unknown"
    if ip.is_multicast:
        return "multicast"
    return "internal" if ip.is_private or ip.is_link_local or ip.is_loopback else "external"


def sha256(path: Path) -> str | None:
    if not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def score_session(folder: Path, det, explainer, top_k: int = 3) -> tuple[pd.DataFrame, dict]:
    """Return a per-flow, pseudonymised verdict table and the session's provenance."""
    manifest = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    flows = pd.read_csv(folder / "validated.csv", low_memory=False)
    X = flows[det.features].apply(pd.to_numeric, errors="coerce")
    pred = det.predict(X)
    proba = det.predict_proba(X).max(axis=1)
    outlier = det.anomaly(X)[1] if det.iforest is not None else np.zeros(len(X), dtype=bool)
    alert = (pred != BENIGN) | outlier
    reasons = [""] * len(flows)
    idx = np.flatnonzero(alert)
    if len(idx):
        explained = explainer.top_features(X.iloc[idx], [pred[i] for i in idx], k=top_k)
        for i, feats in zip(idx, explained):
            text = "; ".join(f"{f['feature']}={f['value']:.4g} ({f['contribution']:+.2f})" for f in feats)
            # SHAP explains the classifier. For an alert raised only by the anomaly detector the classifier
            # said BENIGN, so its SHAP values explain that verdict, not why the flow looked unusual.
            reasons[i] = text if pred[i] != BENIGN else f"anomaly detector only; classifier BENIGN because {text}"
    table = pd.DataFrame({
        "session": manifest.get("session_id", folder.name),
        "time": flows.get("Timestamp"),
        "src": flows.get("Src IP", pd.Series([""] * len(flows))).map(pseudonymise_value),
        "src_scope": flows.get("Src IP", pd.Series([""] * len(flows))).map(scope),
        "dst": flows.get("Dst IP", pd.Series([""] * len(flows))).map(pseudonymise_value),
        "dst_scope": flows.get("Dst IP", pd.Series([""] * len(flows))).map(scope),
        "dst_port": flows["Dst Port"].astype("Int64"),
        "protocol": flows["Protocol"].map(lambda p: PROTOCOLS.get(int(p), str(p))),
        "service": [service_name(p, q) for p, q in zip(flows["Dst Port"], flows["Protocol"])],
        "duration_s": pd.to_numeric(flows["Flow Duration"], errors="coerce") / 1e6,
        "packets": pd.to_numeric(flows["Total Fwd Packet"], errors="coerce")
                   + pd.to_numeric(flows["Total Bwd packets"], errors="coerce"),
        "predicted": pred, "confidence": proba.round(4), "outlier": outlier, "alert": alert,
        "technique": [context_for(p, bool(o)).technique_id or "" if a else "" for p, o, a in zip(pred, outlier, alert)],
        "why": reasons,
    })
    provenance = {"session": manifest.get("session_id", folder.name), "status": manifest.get("status"),
                  "interface": "recorded in private manifest", "capture_sha256": manifest.get("capture_sha256"),
                  "capture_bytes": manifest.get("capture_bytes"), "kept_rows": manifest.get("rows"),
                  "dropped_unusable_rows": manifest.get("dropped_unusable_rows"),
                  "duration_limit_seconds": manifest.get("duration_limit_seconds"),
                  "created_utc": manifest.get("created_utc")}
    return table, provenance


def summarise(table: pd.DataFrame) -> dict:
    n, alerts = len(table), int(table["alert"].sum())
    times = pd.to_datetime(table["time"], format="mixed", errors="coerce").dropna()
    span_h = (times.max() - times.min()).total_seconds() / 3600 if len(times) > 1 else None
    lo, hi = wilson_interval(alerts, n)
    by_service = (table.groupby("service").agg(flows=("alert", "size"), alerts=("alert", "sum"))
                  .sort_values("flows", ascending=False))
    by_service["rate"] = by_service["alerts"] / by_service["flows"]
    flagged = table[table["alert"]]
    return {
        "flows": n, "alerts": alerts, "alert_rate": alerts / n if n else None, "alert_rate_ci": [lo, hi],
        "observed_hours": span_h, "alerts_per_hour": alerts / span_h if span_h else None,
        "external_share": float((table["dst_scope"] == "external").mean()) if n else None,
        "by_service": by_service.reset_index().to_dict("records"),
        "alert_classes": flagged["predicted"].value_counts().to_dict(),
        "anomaly_only": int((flagged["predicted"] == BENIGN).sum()),
        "techniques": flagged["technique"].replace("", "none").value_counts().to_dict(),
    }


def to_markdown(label: str, summary: dict, provenance: list[dict], model: str, alerts: pd.DataFrame) -> str:
    s = summary
    md = [f"# Live capture scoring: {label}", "",
          f"Generated {time.strftime('%Y-%m-%d')} with {model}. Live traffic has no ground truth; no attack traffic "
          "was generated on this network, so every alert below is a **candidate false alarm requiring review**, not a "
          "confirmed false positive. Hosts are pseudonymised; addresses are not recorded here.", "",
          "| Measure | Value |", "|---|---|",
          f"| Flows scored | {s['flows']:,} |",
          f"| Alerts | {s['alerts']:,} |",
          f"| Alert rate | {s['alert_rate']:.1%} (95% interval {s['alert_rate_ci'][0]:.1%}–{s['alert_rate_ci'][1]:.1%}) |"
          if s["alert_rate"] is not None else "| Alert rate | n/a |",
          f"| Observed window | {s['observed_hours'] * 60:.1f} min |" if s["observed_hours"] else "| Observed window | n/a |",
          f"| Alerts per hour at this traffic rate | {s['alerts_per_hour']:.1f} |" if s["alerts_per_hour"] is not None
          else "| Alerts per hour | n/a |",
          f"| Flows to external hosts | {s['external_share']:.0%} |" if s["external_share"] is not None else "",
          f"| Alerts raised by the anomaly detector alone | {s['anomaly_only']} |", "",
          "## By service", "", "| Service | Flows | Alerts | Alert rate |", "|---|---:|---:|---:|"]
    md += [f"| {r['service']} | {r['flows']} | {int(r['alerts'])} | {r['rate']:.0%} |" for r in s["by_service"]]
    md += ["", "## What the alerts were called", "", "| Predicted class | Alerts |", "|---|---:|"]
    md += [f"| {k} | {v} |" for k, v in s["alert_classes"].items()] or ["| none | 0 |"]
    if len(alerts):
        md += ["", "## Alert trace (pseudonymised)", "",
               "| Time (UTC) | Service | Protocol | Src→Dst scope | Predicted | Conf. | Anomaly | Why (top SHAP) |",
               "|---|---|---|---|---|---:|---|---|"]
        for _, a in alerts.head(40).iterrows():
            md.append(f"| {str(a['time'])[:19]} | {a['service']} ({a['dst_port']}) | {a['protocol']} | "
                      f"{a['src_scope']}→{a['dst_scope']} | {a['predicted']} | {a['confidence']:.2f} | "
                      f"{'yes' if a['outlier'] else 'no'} | {a['why']} |")
        if len(alerts) > 40:
            md.append(f"| … {len(alerts) - 40} more in the private per-flow file | | | | | | | |")
    md += ["", "## Provenance", "", "| Session | Created (UTC) | Capture bytes | Kept flows | Dropped as unusable | "
           "Capture SHA-256 (prefix) |", "|---|---|---:|---:|---:|---|"]
    md += [f"| {p['session'][:12]} | {p['created_utc']} | {p['capture_bytes']:,} | {p['kept_rows']} | "
           f"{p['dropped_unusable_rows']} | {str(p['capture_sha256'])[:16]} |" for p in provenance]
    md += ["", "Dropped flows are single-packet, zero-duration flows whose rate features are undefined. "
           "Accuracy, precision and recall are not reported: there are no labels."]
    return "\n".join(line for line in md if line is not None) + "\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("sessions", nargs="+")
    ap.add_argument("--model-dir", default="models")
    ap.add_argument("--label", required=True, help="short description of the network observed, no personal names")
    ap.add_argument("--results", required=True)
    args = ap.parse_args()
    model_dir = Path(args.model_dir)
    det = joblib.load(model_dir / "detector.joblib")
    explainer = Explainer(det)
    tables, provenance = [], []
    for s in args.sessions:
        table, prov = score_session(Path(s), det, explainer)
        table.to_csv(Path(s) / "scored_flows.csv", index=False)
        tables.append(table)
        provenance.append(prov)
    combined = pd.concat(tables, ignore_index=True)
    summary = summarise(combined)
    card = json.loads((model_dir / "model_card.json").read_text(encoding="utf-8"))
    model = f"{det.name.upper()} trained on {card.get('dataset')} (detector SHA-256 {sha256(model_dir / 'detector.joblib')[:16]})"
    out = Path(args.results)
    out.parent.mkdir(parents=True, exist_ok=True)
    alerts = combined[combined["alert"]].sort_values("time")
    out.write_text(to_markdown(args.label, summary, provenance, model, alerts), encoding="utf-8")
    out.with_suffix(".json").write_text(json.dumps({"label": args.label, "model": model, "summary": summary,
                                                     "provenance": provenance}, indent=1, default=str), encoding="utf-8")
    print(f"{summary['flows']} flows, {summary['alerts']} alerts -> {out}")


if __name__ == "__main__":
    main()
