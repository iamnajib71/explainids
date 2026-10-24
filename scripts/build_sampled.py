"""Build a cleaned, benign-sampled Parquet file from a corrected CIC release too large for memory.

Usage: python scripts/build_sampled.py data/raw/csecicids2018 data/processed/csecicids2018.parquet \
           --benign-frac 0.05

CSE-CIC-IDS2018 is ~36 GB of CSV, and almost all of it is benign. Each day's CSV is read in chunks
and cleaned with the same ids.data.clean used for CIC-IDS2017. Every attack flow is kept, and benign
flows are sampled at --benign-frac (seed 42). The result is then deduplicated globally
(ids.data.dedup_global). The benign fraction is saved beside the output so FPR figures stay honest.
"""
import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from ids import SEED
from ids.data import BENIGN, LABEL_COL, clean, dedup_global, feature_columns

KEEP_META = ["Src IP", "Dst IP", "Src Port", "Timestamp", "source_file"]


def sample_chunk(chunk: pd.DataFrame, benign_frac: float, rng: np.random.Generator) -> pd.DataFrame:
    """Keep every attack row and a `benign_frac` random share of benign rows."""
    benign = chunk[LABEL_COL] == BENIGN
    keep = ~benign | (rng.random(len(chunk)) < benign_frac)
    return chunk[keep]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("out")
    ap.add_argument("--benign-frac", type=float, default=0.05)
    ap.add_argument("--chunksize", type=int, default=500_000)
    args = ap.parse_args()

    rng = np.random.default_rng(SEED)
    frames, raw_counts = [], {}
    for path in sorted(Path(args.folder).glob("*.csv")):
        n_raw, kept = 0, 0
        for raw in pd.read_csv(path, chunksize=args.chunksize, low_memory=False):
            raw.columns = [c.strip() for c in raw.columns]
            raw["source_file"] = path.stem
            n_raw += len(raw)
            df = sample_chunk(clean(raw), args.benign_frac, rng)
            feats = feature_columns(df)
            df[feats] = df[feats].astype(np.float32)
            frames.append(df[[c for c in KEEP_META if c in df] + feats + [LABEL_COL]])
            kept += len(df)
        raw_counts[path.stem] = n_raw
        print(f"{path.name}: {n_raw:,} -> {kept:,} rows", flush=True)

    out = pd.concat(frames, ignore_index=True)
    del frames
    before = len(out)
    out = dedup_global(out)
    print(f"global dedup: {before:,} -> {len(out):,} rows")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(args.out, index=False)
    meta = {"source": Path(args.folder).name, "benign_frac": args.benign_frac, "seed": SEED,
            "raw_rows_per_file": raw_counts, "rows": len(out),
            "class_counts": out[LABEL_COL].value_counts().to_dict()}
    Path(args.out).with_suffix(".json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(f"saved {len(out):,} rows x {out.shape[1]} cols to {args.out}")
    print(out[LABEL_COL].value_counts().to_string())


if __name__ == "__main__":
    main()
