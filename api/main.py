"""ExplainIDS API and web console.

Run: uvicorn api.main:app --port 8000   then open http://localhost:8000
Loads models/detector.joblib, models/model_card.json and models/replay.parquet when present (built by
scripts/train_baseline.py from real CIC-IDS data). Without them it falls back to a small demo model
trained on synthetic flows, so the app boots anywhere.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, File, HTTPException, Response, Security, UploadFile
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from ids.alerts import SEVERITY_RANK, aggregate
from ids.data import BENIGN, LABEL_COL, feature_columns
from ids.evaluate import report
from ids.explain import Explainer
from ids.models import Detector
from ids.scoring import align_columns, interleave_background, score_frame
from ids.synthetic import make_flows

MODEL_DIR = Path(os.environ.get("EXPLAINIDS_MODEL_DIR", "models"))
API_KEY = os.environ.get("EXPLAINIDS_API_KEY")  # unset = open (local dev only)
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MAX_UPLOAD_MB, MAX_UPLOAD_ROWS, MAX_RETURNED_ALERTS = 25, 200_000, 300
FLOW_META = {"Src IP": "src", "Dst IP": "dst", "Dst Port": "dport", "Protocol": "proto",
             "Flow Duration": "duration", "Total Fwd Packet": "fwd_pkts", "Total Bwd packets": "bwd_pkts"}

app = FastAPI(title="ExplainIDS API", version="0.2.0",
              description="Explainable intrusion detection with candidate MITRE ATT&CK context.")
_state: dict = {"alerts": []}


def require_key(key: str | None = Security(APIKeyHeader(name="X-API-Key", auto_error=False))):
    if API_KEY and key != API_KEY:
        raise HTTPException(status_code=401, detail="invalid API key")


def _load() -> None:
    if (MODEL_DIR / "detector.joblib").exists():
        det = joblib.load(MODEL_DIR / "detector.joblib")
        card_path, replay_path = MODEL_DIR / "model_card.json", MODEL_DIR / "replay.parquet"
        card = json.loads(card_path.read_text(encoding="utf-8")) if card_path.exists() else {}
        replay = pd.read_parquet(replay_path) if replay_path.exists() else None
        mode = f"trained on {card.get('dataset', 'real data')}"
    else:
        demo = make_flows(150)
        X, y = demo[feature_columns(demo)], demo[LABEL_COL]
        det = Detector("rf").fit(X, y).fit_anomaly(X[y == BENIGN])
        det.tune_anomaly_threshold(X[y == BENIGN])
        card, replay, mode = {"dataset": "synthetic demo", "classes": det.classes, "models": {}}, None, "demo (synthetic)"
    if det.iforest is not None:
        det.iforest.n_jobs = 1  # small live batches: thread start-up costs more than it saves (~1 s/batch)
    if replay is None:
        replay = make_flows(60, seed=7)
    replay["Timestamp"] = pd.to_datetime(replay["Timestamp"], format="mixed").astype(str)
    replay = interleave_background(replay)
    benign = replay[replay[LABEL_COL] == BENIGN][det.features]
    card["benign_median"] = benign.median().round(4).to_dict() if len(benign) else {}
    _state.update(detector=det, explainer=Explainer(det), card=card, replay=replay.reset_index(drop=True), mode=mode)


def state() -> dict:
    if "detector" not in _state:
        _load()
    return _state


def detector() -> Detector:
    return state()["detector"]


class Flows(BaseModel):
    flows: list[dict]


def _flow_rows(df: pd.DataFrame, flows: pd.DataFrame, offset: int = 0) -> list[dict]:
    meta = {new: df[old].tolist() for old, new in FLOW_META.items() if old in df}
    rows = []
    for i in range(len(df)):
        r = {"i": offset + i, "time": str(df["Timestamp"].iat[i]) if "Timestamp" in df else None,
             "predicted": flows["predicted"].iat[i], "confidence": round(float(flows["confidence"].iat[i]), 4),
             "outlier": bool(flows["outlier"].iat[i])}
        r.update({k: (v[i].item() if isinstance(v[i], np.generic) else v[i]) for k, v in meta.items()})
        if "truth" in flows:
            r["truth"] = flows["truth"].iat[i]
        rows.append(r)
    return rows


@app.get("/health")
def health():
    s = state()
    return {"status": "ok", "model": s["mode"], "classifier": s["detector"].name, "replay_flows": len(s["replay"])}


@app.get("/model")
def model_card():
    """Model card: dataset, split, test metrics for every compared model, global SHAP importance."""
    return state()["card"]


@app.get("/replay")
def replay(cursor: int = 0, n: int = 40):
    """Score the next `n` real held-out flows (time-ordered, with ground truth). Wraps at the end.

    Stateless by design: each viewer keeps its own cursor, so many people can watch at once.
    """
    s = state()
    data, total = s["replay"], len(s["replay"])
    n = max(1, min(n, 500))
    idx = [(cursor + j) % total for j in range(n)]
    batch = data.iloc[idx].reset_index(drop=True)
    flows, alerts = score_frame(s["detector"], s["explainer"], batch)
    rows = _flow_rows(batch, flows, offset=cursor)
    for a, r in zip(alerts, [r for r in rows if r["predicted"] != BENIGN or r["outlier"]]):
        a["flow_index"], a["dst"], a["dport"] = r["i"], r.get("dst"), r.get("dport")
        a["values"] = {e["feature"]: e["value"] for e in a["explanation"]}
    return {"cursor": (cursor + n) % total, "total": total, "wrapped": cursor + n >= total,
            "flows": rows, "alerts": alerts}


@app.get("/sample.csv")
def sample_csv(rows: int = 3000):
    """A labelled sample of the replay flows, so visitors can try the upload page end to end."""
    data = state()["replay"]
    sample = data.sample(min(max(rows, 1), 20_000, len(data)), random_state=42).sort_index()
    return Response(sample.to_csv(index=False), media_type="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="explainids_sample_flows.csv"'})


@app.post("/score-csv")
async def score_csv(file: UploadFile = File(...)):
    """Score an uploaded CICFlowMeter CSV. If it has a Label column, return a full evaluation too."""
    raw = await file.read()
    if len(raw) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"file larger than {MAX_UPLOAD_MB} MB")
    try:
        df = pd.read_csv(io.BytesIO(raw), low_memory=False, nrows=MAX_UPLOAD_ROWS)
    except Exception as exc:  # malformed upload: tell the user what went wrong
        raise HTTPException(status_code=422, detail=f"could not read CSV: {exc}") from exc
    det = detector()
    df, missing = align_columns(df, det.features)
    if missing:
        raise HTTPException(status_code=422, detail=f"{len(missing)} model features missing, e.g. {missing[:6]}")
    flows, alerts = score_frame(det, state()["explainer"], df)
    out = {"rows": len(df), "alerts": len(alerts),
           "predicted_counts": flows["predicted"].value_counts().to_dict(),
           "outliers": int(flows["outlier"].sum()),
           "top_alerts": representative(alerts, MAX_RETURNED_ALERTS),
           "incidents": aggregate(alerts)[:100]}
    if "truth" in flows:
        rep = report(flows["truth"], flows["predicted"])
        out["evaluation"] = {"macro": rep["macro"], "benign_fpr": rep["benign_fpr"],
                             "per_class": rep["per_class"].reset_index(names="class").to_dict("records"),
                             "labels": list(rep["confusion"].index), "confusion": rep["confusion"].values.tolist()}
    return out


def representative(alerts: list[dict], n: int) -> list[dict]:
    """Round-robin across predicted classes (most severe first) so one noisy class cannot fill the list."""
    by_class: dict[str, list[dict]] = {}
    for a in sorted(alerts, key=lambda a: (-SEVERITY_RANK.get(a["severity"], 0), -(a["confidence"] or 0))):
        by_class.setdefault(a["predicted_class"], []).append(a)
    queues, out = list(by_class.values()), []
    while queues and len(out) < n:
        out += [q.pop(0) for q in queues][: n - len(out)]
        queues = [q for q in queues if q]
    return out


@app.post("/predict", dependencies=[Depends(require_key)])
def predict(body: Flows):
    if not body.flows:
        raise HTTPException(status_code=422, detail="no flows supplied")
    det = detector()
    df = pd.DataFrame(body.flows)
    missing = [f for f in det.features if f not in df]
    if missing:
        raise HTTPException(status_code=422, detail=f"missing features: {missing[:5]}")
    _, alerts = score_frame(det, state()["explainer"], df)
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


@app.middleware("http")
async def revalidate_static(request, call_next):
    """Make browsers revalidate the console's files so a redeploy shows up on the next load."""
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-cache")
    return response


if WEB_DIR.exists():  # the web console; mounted last so API routes take precedence
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
