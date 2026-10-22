"""Loading, cleaning, label harmonisation and leakage-aware splitting of CICFlowMeter flows.

Designed for the corrected CIC-IDS2017 / CSE-CIC-IDS2018 releases (Liu et al., 2022), whose
"Attempted" labels mark attack flows that carried no attack payload. Per the dataset authors,
they must never become a class of their own; we fold them into BENIGN by default.
"""
from __future__ import annotations

import re
from pathlib import Path

import numpy as np
import pandas as pd

from . import SEED

LABEL_COL = "Label"
BENIGN = "BENIGN"
# Identifier / time columns that must not be model features (leakage and privacy).
ID_COLUMNS = ["Flow ID", "Src IP", "Dst IP", "Src Port", "Timestamp", "Attempted Category", "id"]

# Canonical class names shared by both datasets (and the lab), so cross-dataset tests compare like with like.
_CANON = [
    (r"^benign", BENIGN),
    (r"portscan|port scan", "PortScan"),
    (r"ftp.?(brute|patator)", "FTP-BruteForce"),
    (r"ssh.?(brute|patator)", "SSH-BruteForce"),
    (r"(web.*brute)|(brute force.?-?web)", "Web-BruteForce"),
    (r"xss", "Web-XSS"),
    (r"sql", "Web-SQLInjection"),
    (r"slowloris", "DoS-Slowloris"),
    (r"slowhttp", "DoS-SlowHTTPTest"),
    (r"hulk", "DoS-Hulk"),
    (r"goldeneye", "DoS-GoldenEye"),
    (r"loic.?udp", "DDoS-UDP"),
    (r"loic|hoic|ddos", "DDoS-HTTP"),
    (r"heartbleed", "Heartbleed"),
    (r"infil", "Infiltration"),
    (r"bot", "Bot"),
]


def canonical_label(raw: str, attempted_as_benign: bool = True) -> str:
    text = str(raw).strip()
    if re.search(r"attempted", text, re.I):
        if attempted_as_benign:
            return BENIGN
        text = re.sub(r"\s*-?\s*attempted", "", text, flags=re.I)
    low = text.lower()
    for pattern, name in _CANON:
        if re.search(pattern, low):
            return name
    return text


def load_csvs(folder: str | Path, nrows: int | None = None) -> pd.DataFrame:
    frames = []
    for path in sorted(Path(folder).rglob("*.csv")):
        df = pd.read_csv(path, nrows=nrows, low_memory=False)
        df.columns = [c.strip() for c in df.columns]
        df["source_file"] = path.name
        frames.append(df)
    if not frames:
        raise FileNotFoundError(f"No CSV files under {folder}")
    return pd.concat(frames, ignore_index=True)


def clean(df: pd.DataFrame, attempted_as_benign: bool = True) -> pd.DataFrame:
    """Harmonise labels, coerce numerics, drop NaN/inf rows and exact duplicate feature rows."""
    out = df.copy()
    out[LABEL_COL] = out[LABEL_COL].map(lambda v: canonical_label(v, attempted_as_benign))
    feats = feature_columns(out)
    out[feats] = out[feats].apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    out = out.dropna(subset=feats)
    return out.drop_duplicates(subset=feats + [LABEL_COL]).reset_index(drop=True)


def feature_columns(df: pd.DataFrame) -> list[str]:
    skip = set(ID_COLUMNS) | {LABEL_COL, "source_file", "session"}
    return [c for c in df.columns if c not in skip]


def add_sessions(df: pd.DataFrame, minutes: int = 30) -> pd.DataFrame:
    """Group flows into capture sessions (file + time window) so related flows never straddle splits."""
    out = df.copy()
    if "Timestamp" in out:
        ts = pd.to_datetime(out["Timestamp"], errors="coerce", format="mixed")
        bucket = ts.dt.floor(f"{minutes}min").astype(str)
    else:
        bucket = (out.index // 1000).astype(str)
    source = out["source_file"].astype(str) if "source_file" in out else "all"
    out["session"] = source + "|" + bucket
    return out


def session_split(df: pd.DataFrame, test_size: float = 0.2, val_size: float = 0.1, seed: int = SEED):
    """Split by session, per class, so every class appears in train/val/test where possible.

    Sessions are assigned to a split as whole units (no flow-level leakage). For each class we
    shuffle the sessions containing it and allocate them; a session goes to the split chosen
    first (by its majority class), which keeps the procedure deterministic.
    """
    if "session" not in df:
        df = add_sessions(df)
    rng = np.random.default_rng(seed)
    majority = df.groupby("session")[LABEL_COL].agg(lambda s: s.value_counts().idxmax())
    assignment: dict[str, str] = {}
    for label, sessions in majority.groupby(majority):
        ids = sessions.index.to_numpy()
        rng.shuffle(ids)
        n = len(ids)
        n_test = max(1, round(n * test_size)) if n >= 3 else (1 if n == 2 else 0)
        n_val = max(1, round(n * val_size)) if n >= 3 else 0
        for i, sid in enumerate(ids):
            assignment[sid] = "test" if i < n_test else ("val" if i < n_test + n_val else "train")
    split = df["session"].map(assignment)
    return df[split == "train"], df[split == "val"], df[split == "test"]


def temporal_split(df: pd.DataFrame, test_size: float = 0.2, val_size: float = 0.1):
    """Chronological split within each class: earliest flows train, then validation, latest test.

    CIC captures run each attack as one burst from a single attacker, so random or session-level
    splits either leak near-duplicate flows or drop whole classes from the test set. Splitting each
    class in time order keeps every class in every split and makes the model predict the *later*
    part of each attack from its earlier part (no future information in training).
    """
    ts = pd.to_datetime(df["Timestamp"], errors="coerce", format="mixed")
    order = ts.groupby(df[LABEL_COL]).rank(method="first", pct=True)
    train = order <= 1 - test_size - val_size
    test = order > 1 - test_size
    return df[train], df[~train & ~test], df[test]


def stratified_sample(df: pd.DataFrame, per_class: int, seed: int = SEED) -> pd.DataFrame:
    """Cap each class at `per_class` rows (keeps rare classes whole) to fit laptop memory."""
    parts = [g.sample(min(len(g), per_class), random_state=seed) for _, g in df.groupby(LABEL_COL)]
    return pd.concat(parts).sample(frac=1, random_state=seed).reset_index(drop=True)
