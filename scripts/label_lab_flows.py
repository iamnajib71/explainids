"""Label flows captured in the isolated attack lab, using the attack schedule kept during the session.

Usage:
  python scripts/label_lab_flows.py lab/flows.csv lab/attack_schedule.csv lab/flows_labelled.csv --pad 2

A flow gets a scenario's label when it runs between that scenario's attacker and victim (either
direction) and starts inside the scenario's time window, widened by --pad seconds for clock skew.
Every other flow is BENIGN. Labels are canonicalised with ids.data.canonical_label, so "SSH brute
force" and "SSH-BruteForce" mean the same class as in the benchmark datasets. A label with no
benchmark counterpart (e.g. "SYN-Flood") is kept as is: it is an unseen class for RQ3.

Schedule columns: scenario, label, attacker_ip, victim_ip, start, end (any other columns are kept for
the record, e.g. the exact command run). Times must use the same clock as the capture (the victim VM).
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import pandas as pd

from ids.data import BENIGN, LABEL_COL, canonical_label

SCHEDULE_COLS = ["scenario", "label", "attacker_ip", "victim_ip", "start", "end"]


def _norm(name: str) -> str:
    return re.sub(r"[^a-z]", "", name.lower())


def find_column(df: pd.DataFrame, *names: str) -> str:
    """Locate a CICFlowMeter column whatever its spacing or case ('Src IP', 'src_ip', ...)."""
    wanted = {_norm(n) for n in names}
    for col in df.columns:
        if _norm(col) in wanted:
            return col
    raise KeyError(f"no column like {names[0]!r}; columns are {list(df.columns)[:8]}...")


def label_flows(flows: pd.DataFrame, schedule: pd.DataFrame, pad_s: float = 2.0, dayfirst: bool = False) -> pd.DataFrame:
    missing = [c for c in SCHEDULE_COLS if c not in schedule]
    if missing:
        raise ValueError(f"schedule is missing columns {missing}")
    src, dst = find_column(flows, "Src IP", "Source IP"), find_column(flows, "Dst IP", "Destination IP")
    ts = pd.to_datetime(flows[find_column(flows, "Timestamp")], format="mixed", dayfirst=dayfirst, errors="coerce")
    if ts.isna().any():
        raise ValueError(f"{int(ts.isna().sum())} flow timestamps could not be parsed; try --dayfirst")
    pad = pd.Timedelta(seconds=pad_s)
    labels = pd.Series(BENIGN, index=flows.index, dtype=object)
    for row in schedule.itertuples(index=False):
        start = pd.to_datetime(row.start, dayfirst=dayfirst) - pad
        end = pd.to_datetime(row.end, dayfirst=dayfirst) + pad
        pair = (((flows[src] == row.attacker_ip) & (flows[dst] == row.victim_ip))
                | ((flows[src] == row.victim_ip) & (flows[dst] == row.attacker_ip)))
        hit = pair & ts.between(start, end)
        clash = hit & (labels != BENIGN)
        if clash.any():
            raise ValueError(f"scenario {row.scenario!r} overlaps another scenario on {int(clash.sum())} flows")
        labels[hit] = canonical_label(row.label)
    out = flows.copy()
    out[LABEL_COL] = labels
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("flows")
    ap.add_argument("schedule")
    ap.add_argument("out")
    ap.add_argument("--pad", type=float, default=2.0, help="seconds added before/after each window")
    ap.add_argument("--dayfirst", action="store_true", help="timestamps like 31/10/2026 14:05:00")
    args = ap.parse_args()
    flows = pd.read_csv(args.flows, low_memory=False)
    flows.columns = [c.strip() for c in flows.columns]
    out = label_flows(flows, pd.read_csv(args.schedule), args.pad, args.dayfirst)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.out, index=False)
    print(f"labelled {len(out):,} flows -> {args.out}")
    print(out[LABEL_COL].value_counts().to_string())


if __name__ == "__main__":
    main()
