"""Small synthetic CICFlowMeter-style data for tests and the dashboard demo (no real traffic)."""
from __future__ import annotations

import numpy as np
import pandas as pd

from . import SEED

FEATURES = ["Dst Port", "Protocol", "Flow Duration", "Total Fwd Packet", "Total Bwd packets",
            "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "RST Flag Count", "Packet Length Mean"]

_PROFILES = {  # class: (dst_port, mean duration, fwd pkts, syn, rst, pkt len)
    "BENIGN": (443, 50_000, 12, 1, 0, 600),
    "PortScan": (None, 80, 1, 1, 1, 0),
    "SSH-BruteForce": (22, 3_000, 22, 1, 0, 90),
    "DoS-Hulk": (80, 9_000, 6, 1, 0, 380),
    "DDoS-UDP": (53, 15, 40, 0, 0, 1200),
}


def make_flows(n_per_class: int = 200, seed: int = SEED, start: str = "2026-10-20 09:00") -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows = []
    t0 = pd.Timestamp(start)
    for k, (label, (port, dur, fwd, syn, rst, plen)) in enumerate(_PROFILES.items()):
        for i in range(n_per_class):
            d = max(1.0, rng.normal(dur, dur * 0.2))
            f = max(1, int(rng.normal(fwd, max(1, fwd * 0.2))))
            b = max(0, int(rng.normal(f * 0.8, 2)))
            rows.append({
                "Flow ID": f"f{k}-{i}", "Src IP": f"192.168.56.{10 + k}", "Dst IP": "192.168.56.20",
                "Src Port": int(rng.integers(1024, 65535)),
                "Dst Port": int(rng.integers(1, 1024)) if port is None else port,
                "Protocol": 17 if label == "DDoS-UDP" else 6,
                "Timestamp": str(t0 + pd.Timedelta(minutes=int(k * 40 + i // 10))),
                "Flow Duration": d, "Total Fwd Packet": f, "Total Bwd packets": b,
                "Flow Bytes/s": (f + b) * plen / d * 1e6, "Flow Packets/s": (f + b) / d * 1e6,
                "SYN Flag Count": syn, "RST Flag Count": rst,
                "Packet Length Mean": max(0.0, rng.normal(plen, plen * 0.1 + 1)),
                "Label": label,
            })
    return pd.DataFrame(rows).sample(frac=1, random_state=seed).reset_index(drop=True)
