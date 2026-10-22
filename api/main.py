"""ExplainIDS scoring API.

Run: uvicorn api.main:app --reload
Loads models/detector.joblib if present; otherwise trains a small demo model on synthetic flows
so the API and dashboard can be developed before the real models exist (mock alert format).
"""
from __future__ import annotations

import os
from pathlib import Path

import joblib
import pandas as pd
from fastapi import Depends, FastAPI, HTTPException, Security
from fastapi.security import APIKeyHeader
from pydantic import BaseModel

from ids.alerts import aggregate, build_alerts
from ids.data import BENIGN, LABEL_COL, feature_columns
from ids.models import Detector
from ids.synthetic import make_flows

MODEL_PATH = Path(os.environ.get("EXPLAINIDS_MODEL", "models/detector.joblib"))
API_KEY = os.environ.get("EXPLAINIDS_API_KEY")  # unset = open (local dev only)

app = FastAPI(title="ExplainIDS API", version="0.1.0")
_state: dict = {"alerts": []}


def require_key(key: str | None = Security(APIKeyHeader(name="X-API-Key", auto_error=False))):
    if API_KEY and key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


def detector() -> Detector:
    if "detector" not in _state:
        if MODEL_PATH.exists():
            _state["detector"] = joblib.load(MODEL_PATH)
            _state["mode"] = "trained"
        else:
            demo = make_flows(150)
            X, y = demo[feature_columns(demo)], demo[LABEL_COL]
            det = Detector("rf").fit(X, y).fit_anomaly(X[y == BENIGN])
            det.tune_anomaly_threshold(X[y == BENIGN])
            _state["detector"], _state["mode"] = det, "demo (synthetic)"
    return _state["detector"]


class Flows(BaseModel):
    flows: list[dict]


@app.get("/health")
def health():
    detector()
    return {"status": "ok", "model": _state["mode"]}


@app.post("/predict", dependencies=[Depends(require_key)])
def predict(body: Flows):
    if not body.flows:
        raise HTTPException(status_code=422, detail="no flows supplied")
    det = detector()
    df = pd.DataFrame(body.flows)
    missing = [f for f in det.features if f not in df]
    if missing:
        raise HTTPException(status_code=422, detail=f"missing features: {missing[:5]}")
    pred, proba = det.predict(df), det.predict_proba(df)
    scores, outliers = det.anomaly(df) if det.iforest is not None else (None, None)
    alerts = build_alerts(df, pred, proba, scores, outliers)
    _state["alerts"].extend(alerts)
    return {"scored": len(df), "alerts": alerts}


@app.get("/alerts", dependencies=[Depends(require_key)])
def alerts(limit: int = 200):
    return _state["alerts"][-limit:]


@app.get("/incidents", dependencies=[Depends(require_key)])
def incidents(window_minutes: int = 10):
    return aggregate(_state["alerts"], window_minutes)


@app.post("/alerts/{alert_id}/status", dependencies=[Depends(require_key)])
def set_status(alert_id: str, status: str):
    if status not in {"open", "confirmed", "dismissed"}:
        raise HTTPException(status_code=422, detail="status must be open, confirmed or dismissed")
    for a in _state["alerts"]:
        if a["alert_id"] == alert_id:
            a["status"] = status
            return a
    raise HTTPException(status_code=404, detail="alert not found")
