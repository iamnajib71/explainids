"""Profile a corrected CIC-IDS release: columns, raw labels, canonical labels and clean-up effects.

Usage: python scripts/profile_dataset.py data/raw/cicids2017 [--sample-rows 200000]
"""
import argparse
from collections import Counter

import pandas as pd

from ids.data import LABEL_COL, canonical_label, clean, feature_columns, load_csvs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("folder")
    ap.add_argument("--sample-rows", type=int, default=None, help="rows read per CSV (default: all)")
    args = ap.parse_args()

    df = load_csvs(args.folder, nrows=args.sample_rows)
    print(f"rows: {len(df):,}  columns: {len(df.columns)}")
    print("non-feature columns:", [c for c in df.columns if c not in feature_columns(df)])
    print("\nraw labels:")
    for label, n in Counter(df[LABEL_COL]).most_common():
        print(f"  {n:>10,}  {label!r:45} -> {canonical_label(label)}")
    cleaned = clean(df)
    print(f"\nafter clean: {len(cleaned):,} rows ({len(df) - len(cleaned):,} removed: NaN/inf/duplicates)")
    print(cleaned[LABEL_COL].value_counts().to_string())
    print(f"\nfeatures used: {len(feature_columns(cleaned))}")


if __name__ == "__main__":
    pd.set_option("display.width", 160)
    main()
