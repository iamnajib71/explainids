"""Durable analyst triage decisions, and the repair set they produce.

Each decision is kept in a local SQLite file with the alert's model features. A dismissed alert is an
analyst's confirmation that the flow was benign; those flows are the repair set that, in the thesis
experiments, removes service-shaped false alarms after the detector moves to a new network
(docs/RESEARCH.md). No addresses are stored: only model features, the model's verdict and the decision.

The repair set is also an attack surface: three attacks wrongly dismissed were enough to blind a retrained
model to their type (docs/RESEARCH.md, E10). A dismissal is therefore marked `repair_eligible` only if the
flow resembles the site's normal traffic; ineligible dismissals are kept as decisions but held back from
retraining. Eligibility is unknown (NULL) when no site envelope was attached at decision time.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from .data import BENIGN, LABEL_COL

STATUSES = {"open", "confirmed", "dismissed"}
_SCHEMA = """CREATE TABLE IF NOT EXISTS decisions (
    alert_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    decided_utc TEXT NOT NULL,
    predicted_class TEXT,
    outlier INTEGER,
    features TEXT,
    repair_eligible INTEGER
)"""


class TriageStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(_SCHEMA)
            if "repair_eligible" not in {r[1] for r in db.execute("PRAGMA table_info(decisions)")}:
                db.execute("ALTER TABLE decisions ADD COLUMN repair_eligible INTEGER")  # stores made before the gate

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=10)

    def record(self, alert_id: str, status: str, predicted_class: str | None = None,
               outlier: bool | None = None, features: dict | None = None,
               repair_eligible: bool | None = None) -> None:
        """Insert or update one decision; features are kept from the first time they were supplied."""
        if status not in STATUSES:
            raise ValueError(f"status must be one of {sorted(STATUSES)}")
        now = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(features) if features else None
        with self._lock, self._connect() as db:
            db.execute(
                """INSERT INTO decisions (alert_id, status, decided_utc, predicted_class, outlier, features,
                                          repair_eligible)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(alert_id) DO UPDATE SET status = excluded.status,
                       decided_utc = excluded.decided_utc,
                       features = COALESCE(decisions.features, excluded.features),
                       repair_eligible = COALESCE(excluded.repair_eligible, decisions.repair_eligible)""",
                (alert_id, status, now, predicted_class, None if outlier is None else int(outlier), payload,
                 None if repair_eligible is None else int(repair_eligible)))

    def status(self, alert_id: str) -> str | None:
        with self._connect() as db:
            row = db.execute("SELECT status FROM decisions WHERE alert_id = ?", (alert_id,)).fetchone()
        return row[0] if row else None

    def summary(self) -> dict:
        with self._connect() as db:
            counts = dict(db.execute("SELECT status, COUNT(*) FROM decisions GROUP BY status").fetchall())
            usable, held, ungated = db.execute(
                "SELECT COALESCE(SUM(repair_eligible IS NOT 0), 0), COALESCE(SUM(repair_eligible = 0), 0), "
                "COALESCE(SUM(repair_eligible IS NULL), 0) FROM decisions "
                "WHERE status = 'dismissed' AND features IS NOT NULL").fetchone()
        return {"decisions": {s: counts.get(s, 0) for s in sorted(STATUSES)}, "repair_set_flows": usable,
                "held_back": held, "ungated": ungated}

    def repair_set(self) -> pd.DataFrame:
        """Dismissed alerts with features, labelled benign: the flows an analyst confirmed were normal.
        Dismissals outside the site's normal traffic (repair_eligible = 0) are held back."""
        with self._connect() as db:
            rows = db.execute("SELECT alert_id, predicted_class, features FROM decisions "
                              "WHERE status = 'dismissed' AND features IS NOT NULL AND repair_eligible IS NOT 0 "
                              "ORDER BY decided_utc").fetchall()
        if not rows:
            return pd.DataFrame()
        frame = pd.DataFrame([json.loads(f) for _, _, f in rows])
        frame["alert_id"] = [a for a, _, _ in rows]
        frame["model_said"] = [p for _, p, _ in rows]
        frame[LABEL_COL] = BENIGN
        return frame
