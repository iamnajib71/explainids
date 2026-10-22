"""Convert a corrected CIC-IDS release (folder of CSVs) into one cleaned, float32 Parquet file.

Usage: python scripts/build_processed.py data/raw/cicids2017 data/processed/cicids2017.parquet
Cleaning is per file (labels harmonised, NaN/inf and duplicate rows dropped) to keep memory low.
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd

from ids.data import LABEL_COL, clean, feature_columns

KEEP_META = ["Src IP", "Dst IP", "Src Port", "Timestamp", "source_file"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("out")
    args = ap.parse_args()

    frames = []
    for path in sorted(Path(args.folder).glob("*.csv")):
        raw = pd.read_csv(path, low_memory=False)
        raw.columns = [c.strip() for c in raw.columns]
        raw["source_file"] = path.stem
        df = clean(raw)
        feats = feature_columns(df)
        df[feats] = df[feats].astype(np.float32)
        frames.append(df[[c for c in KEEP_META if c in df] + feats + [LABEL_COL]])
        print(f"{path.name}: {len(raw):,} -> {len(df):,} rows", flush=True)
        del raw
    out = pd.concat(frames, ignore_index=True)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(args.out, index=False)
    print(f"saved {len(out):,} rows x {out.shape[1]} cols to {args.out}")
    print(out[LABEL_COL].value_counts().to_string())


if __name__ == "__main__":
    main()
