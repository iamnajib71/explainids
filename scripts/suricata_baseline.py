"""A rule-based baseline: Suricata with the Emerging Threats Open ruleset on the same recordings.

  docker run --rm --entrypoint sh -v <pcaps>:/pcaps:ro -v <out>:/out jasonish/suricata:latest -c \
      'suricata-update -q --no-test; suricata -r /pcaps -k none -l /out -S /var/lib/suricata/rules/suricata.rules'
  python scripts/suricata_baseline.py --evening data/suricata/20261108 --hours 0.99 \
      --lab-default data/suricata/lab --lab-external data/suricata/lab_ext --lab-root data/lab

Reads Suricata's eve.json and writes aggregates only (signature names and counts; no addresses, no per-flow rows).
Lab alerts are matched to the attack schedule by time. "Capture artefact" means the checksum events that NIC
offload produces on the capturing host; they are counted separately because a deployment would switch them off.
Accuracy is never reported (rule 4).
"""
from __future__ import annotations

import argparse
import collections
import json
import time
from pathlib import Path

import pandas as pd

ATTACK_RUNS = ["050509Z", "050628Z", "051149Z"]
BENIGN_RUNS = ["051701Z", "051751Z"]


def alerts(folder: Path) -> tuple[list[tuple], int]:
    out, flows = [], 0
    for line in (folder / "eve.json").open(encoding="utf-8"):
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") == "flow":
            flows += 1
        elif e.get("event_type") == "alert":
            ts = pd.Timestamp(e["timestamp"]).tz_convert("UTC").tz_localize(None)
            out.append((ts, e["alert"]["signature"], e.get("flow_id")))
    return out, flows


def kind(sig: str) -> str:
    if "invalid checksum" in sig:
        return "capture artefact (checksum)"
    return "protocol anomaly" if sig.startswith("SURICATA") else "ruleset signature"


def evening(folder: Path, hours: float) -> dict:
    ev, flows = alerts(folder)
    by = collections.Counter(kind(s) for _, s, _ in ev)
    rule = collections.Counter(s for _, s, _ in ev if kind(s) == "ruleset signature")
    rule_flows = len({f for _, s, f in ev if kind(s) == "ruleset signature"})
    return {"flows": flows, "alerts": len(ev), "by_kind": dict(by), "hours": hours, "rule_signatures": dict(rule),
            "rule_flows": rule_flows, "alerting_flows": len({f for _, _, f in ev})}


def lab(root: Path, lab_root: Path) -> dict:
    out = {"attacks": {}, "benign": {}}
    for run in ATTACK_RUNS + BENIGN_RUNS:
        ev, _ = alerts(root / run)
        ev = [x for x in ev if kind(x[1]) != "capture artefact (checksum)"]
        sched = pd.read_csv(lab_root / f"run_20261025T{run}" / "attack_schedule_scoring.csv", parse_dates=["start", "end"])
        for _, s in sched.iterrows():
            hit = collections.Counter(sig for t, sig, _ in ev if s.start <= t <= s.end + pd.Timedelta(seconds=2))
            bucket = out["benign" if s.label == "BENIGN" else "attacks"].setdefault(s.label, [])
            bucket.append(dict(hit))
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evening", type=Path, required=True)
    ap.add_argument("--hours", type=float, required=True)
    ap.add_argument("--lab-default", type=Path, required=True)
    ap.add_argument("--lab-external", type=Path, required=True)
    ap.add_argument("--lab-root", type=Path, default=Path("data/lab"))
    ap.add_argument("--results", default="docs/results/suricata_baseline.md")
    args = ap.parse_args()
    res = {"generated": time.strftime("%Y-%m-%d"), "evening": evening(args.evening, args.hours),
           "lab_default": lab(args.lab_default, args.lab_root), "lab_external": lab(args.lab_external, args.lab_root)}
    out = Path(args.results)
    out.with_suffix(".json").write_text(json.dumps(res, indent=1), encoding="utf-8")
    out.write_text(to_markdown(res), encoding="utf-8")
    print(to_markdown(res))


def to_markdown(res: dict) -> str:
    e = res["evening"]
    L = ["# Rule-based baseline: Suricata with Emerging Threats Open", "",
         f"Generated on {res['generated']}. Suricata 8.0.8 (Docker image `jasonish/suricata`), default configuration, "
         "ET Open rules as downloaded that day, checksum validation off (`-k none`). Aggregates only.", "",
         f"## Real home evening, 8 November ({e['hours']:.2f} h of traffic, {e['flows']:,} flows)", "",
         "| Alert kind | Alerts | Per hour |", "|---|---|---|"]
    for k, v in sorted(e["by_kind"].items(), key=lambda kv: -kv[1]):
        L.append(f"| {k} | {v:,} | {v / e['hours']:,.0f} |")
    L += [f"| **All** | **{e['alerts']:,}** | **{e['alerts'] / e['hours']:,.0f}** |", "",
          f"Ruleset signatures fired on {e['rule_flows']} flows, all informational: "
          + "; ".join(f"{k} ({v})" for k, v in sorted(e["rule_signatures"].items(), key=lambda kv: -kv[1])) + ".", "",
          "## Isolated lab: three attack replicates and two all-benign service captures", "",
          "| Lab scenario | Default settings: replicates with an alert | Attacker marked external: replicates with an alert | Signatures |",
          "|---|---|---|---|"]
    for label in res["lab_external"]["attacks"]:
        d, x = res["lab_default"]["attacks"][label], res["lab_external"]["attacks"][label]
        sigs = sorted({s for h in x for s in h})
        L.append(f"| {label} | {sum(bool(h) for h in d)} of {len(d)} | {sum(bool(h) for h in x)} of {len(x)} | "
                 f"{'; '.join(sigs) or 'none'} |")
    for label, x in res["lab_external"]["benign"].items():
        d = res["lab_default"]["benign"][label]
        tot = collections.Counter()
        for h in x:
            tot.update(h)
        L.append(f"| {label} windows (false alerts) | {sum(sum(h.values()) for h in d)} alerts | "
                 f"{sum(tot.values())} alerts | {'; '.join(f'{k} ({v})' for k, v in tot.most_common())} |")
    L += ["", "Accuracy is not reported (rule 4). No addresses or per-flow records."]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
