"""Keyed pseudonymisation of IP addresses before any data leaves the lab machine (SR2)."""
from __future__ import annotations

import hashlib
import hmac
import os

import pandas as pd

IP_COLUMNS = ("Src IP", "Dst IP")


def _key() -> bytes:
    key = os.environ.get("EXPLAINIDS_PSEUDO_KEY")
    if not key:
        raise RuntimeError("Set EXPLAINIDS_PSEUDO_KEY (kept out of the repository) before pseudonymising.")
    return key.encode()


def pseudonymise_value(value: str, key: bytes | None = None) -> str:
    digest = hmac.new(key or _key(), str(value).encode(), hashlib.sha256).hexdigest()
    return f"host-{digest[:10]}"


def pseudonymise(df: pd.DataFrame, key: bytes | None = None) -> pd.DataFrame:
    out = df.copy()
    k = key or _key()
    for col in IP_COLUMNS:
        if col in out:
            out[col] = out[col].map(lambda v: pseudonymise_value(v, k))
    return out
