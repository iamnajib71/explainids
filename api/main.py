"""ExplainIDS API and web console.

Run: uvicorn api.main:app --port 8000   then open http://localhost:8000
Loads models/detector.joblib, models/model_card.json and models/replay.parquet when present (built by
scripts/train_baseline.py from real CIC-IDS data). Without them it falls back to a small demo model
trained on synthetic flows, so the app boots anywhere.
"""
from __future__ import annotations

import io
import csv
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, File, Form, HTTPException, Response, Security, UploadFile
from fastapi.security import APIKeyHeader
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from ids.alerts import SEVERITY_RANK, aggregate
from ids.data import BENIGN, LABEL_COL, feature_columns
from ids.evaluate import report
from ids.explain import Explainer
from ids.models import Detector
from ids.scoring import align_columns, interleave_background, score_frame
from ids.synthetic import make_flows
from ids.triage_store import STATUSES, TriageStore

MODEL_DIR = Path(os.environ.get("EXPLAINIDS_MODEL_DIR", "models"))
API_KEY = os.environ.get("EXPLAINIDS_API_KEY")  # unset = open (local dev only)
WEB_DIR = Path(__file__).resolve().parent.parent / "web"
MAX_UPLOAD_MB, MAX_UPLOAD_ROWS, MAX_RETURNED_ALERTS = 25, 200_000, 300
MAX_PREDICT_FLOWS, MAX_KEPT_ALERTS = 1000, 10_000
MAX_SENSOR_BYTES, MAX_SENSOR_ROWS, MAX_SENSOR_KEPT = 5 * 1024 * 1024, 1000, 2000
_sensor_lock = threading.RLock()
_sensor_key = secrets.token_bytes(32)  # local process lifetime; never return addresses or hostname
_sensor: dict = {"rows": [], "alerts": [], "seq": 0, "batches": [], "summary": None}
FLOW_META = {"Src IP": "src", "Dst IP": "dst", "Dst Port": "dport", "Protocol": "proto",
             "Flow Duration": "duration", "Total Fwd Packet": "fwd_pkts", "Total Bwd packets": "bwd_pkts"}

app = FastAPI(title="ExplainIDS API", version="0.2.0",
              description="Explainable intrusion detection with candidate MITRE ATT&CK context.")
_state: dict = {"alerts": []}
_alert_features: dict[str, dict] = {}  # alert_id -> model features, kept only for triage
TRIAGE_DB = Path(os.environ.get("EXPLAINIDS_TRIAGE_DB", "data/triage.sqlite"))
_triage_store: TriageStore | None = None


def triage() -> TriageStore:
    global _triage_store
    if _triage_store is None or _triage_store.path != TRIAGE_DB:
        _triage_store = TriageStore(TRIAGE_DB)
    return _triage_store


def _remember(alerts: list[dict], frame: pd.DataFrame, flagged: list[int]) -> None:
    """Keep each new alert's model features so a later triage decision can feed the repair set."""
    feats = detector().features
    for a, i in zip(alerts, flagged):
        _alert_features[a["alert_id"]] = {f: float(frame[f].iat[i]) for f in feats}
    while len(_alert_features) > MAX_KEPT_ALERTS:
        _alert_features.pop(next(iter(_alert_features)))


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
    flows: list[dict] = Field(max_length=MAX_PREDICT_FLOWS)


def _flow_rows(df: pd.DataFrame, flows: pd.DataFrame, offset: int = 0) -> list[dict]:
    meta = {new: df[old].tolist() for old, new in FLOW_META.items() if old in df}
    rows = []
    for i in range(len(df)):
        r = {"i": offset + i, "time": str(df["Timestamp"].iat[i]) if "Timestamp" in df else None,
             "predicted": flows["predicted"].iat[i], "confidence": round(float(flows["confidence"].iat[i]), 4),
             "outlier": bool(flows["outlier"].iat[i]),
             "demoted": bool(flows["demoted"].iat[i]) if "demoted" in flows else False}
        r.update({k: (v[i].item() if isinstance(v[i], np.generic) else v[i]) for k, v in meta.items()})
        if "truth" in flows:
            r["truth"] = flows["truth"].iat[i]
        rows.append(r)
    return rows


@app.get("/health")
def health():
    s = state()
    return {"status": "ok", "model": s["mode"], "classifier": s["detector"].name,
            "replay_flows": len(s["replay"]), "sensor_key_required": bool(API_KEY)}


def _sensor_token(value: str, name: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", value):
        raise HTTPException(status_code=422, detail=f"{name} must be a 1–64 character token")
    return value


def _private_host(value: object) -> str:
    digest = hmac.new(_sensor_key, str(value).encode(), hashlib.sha256).hexdigest()
    return "host-" + digest[:12]


@app.post("/sensor/ingest", dependencies=[Depends(require_key)])
async def sensor_ingest(file: UploadFile = File(...), sensor_session: str = Form("local"),
                        batch_id: str = Form(""), sensor_id: str = Form("local"),
                        session_stats: str = Form("{}")):
    """Accept already-extracted observations; this endpoint never starts packet capture.

    Sender provenance is self-reported. A valid feature schema is not proof of live capture or attack.
    Labels and extra input columns are discarded; no ground-truth metrics are inferred.
    """
    sensor_session = _sensor_token(sensor_session, "sensor_session")
    if len(sensor_id) > 64 or len(session_stats) > 512:
        raise HTTPException(status_code=422, detail="sensor metadata too large")
    try:
        supplied = json.loads(session_stats)
        if not isinstance(supplied, dict):
            raise ValueError("object required")
        stats = {k: v for k, v in supplied.items() if k in {"captured_packets", "dropped_packets"}}
        if any(type(v) is not int or not 0 <= v <= 10**12 for v in stats.values()):
            raise ValueError("non-negative bounded integer counts required")
    except (ValueError, TypeError):
        raise HTTPException(status_code=422, detail="invalid session_stats") from None
    raw = await file.read(MAX_SENSOR_BYTES + 1)
    if len(raw) > MAX_SENSOR_BYTES:
        raise HTTPException(status_code=413, detail="sensor batch exceeds 5 MB")
    checksum = hashlib.sha256(raw).hexdigest()
    batch_id = _sensor_token(batch_id or checksum[:24], "batch_id")
    batch_key = (sensor_session, batch_id)
    with _sensor_lock:
        previous = next((b for b in _sensor["batches"] if b["key"] == batch_key), None)
        if previous:
            if previous["checksum"] != checksum:
                raise HTTPException(status_code=409, detail="batch_id reused with different data")
            return {**previous["result"], "duplicate": True}
    try:
        text = raw.decode("utf-8-sig")
        header = next(csv.reader(io.StringIO(text, newline="")))
        if len(header) != len(set(header)):
            raise ValueError("duplicate columns")
        df = pd.read_csv(io.StringIO(text), nrows=MAX_SENSOR_ROWS + 1)
    except (UnicodeError, ValueError, StopIteration, csv.Error, pd.errors.ParserError):
        raise HTTPException(status_code=422, detail="invalid sensor CSV or duplicate columns") from None
    if not 1 <= len(df) <= MAX_SENSOR_ROWS:
        raise HTTPException(status_code=413 if len(df) > MAX_SENSOR_ROWS else 422,
                            detail="sensor batch requires 1–1000 rows")
    det = detector()
    if state()["mode"].startswith("demo"):
        raise HTTPException(status_code=503, detail="local sensor requires a saved trained model; synthetic demo is replay only")
    df, missing = align_columns(df, det.features)
    if missing or df.columns.duplicated().any():
        raise HTTPException(status_code=422, detail=f"missing or ambiguous model features: {missing[:6]}")
    numeric = df[det.features].apply(pd.to_numeric, errors="coerce")
    if not np.isfinite(numeric.to_numpy(dtype=float)).all():
        raise HTTPException(status_code=422, detail="sensor features must all be finite numeric values; no rows accepted")
    # Keep only approved numeric model fields and bounded, pseudonymised display metadata.
    frame = numeric.copy()
    for col in ("Src IP", "Dst IP"):
        frame[col] = df[col].astype(str).map(_private_host) if col in df else _private_host("unknown")
    if "Timestamp" in df:
        times = pd.to_datetime(df["Timestamp"], errors="coerce", utc=True, format="mixed")
        if times.isna().any():
            raise HTTPException(status_code=422, detail="invalid sensor timestamps")
        frame["Timestamp"] = times.astype(str)
    else:
        frame["Timestamp"] = datetime.now(timezone.utc).isoformat()
    flows, new_alerts = await run_in_threadpool(score_frame, det, state()["explainer"], frame)
    rows = _flow_rows(frame, flows)
    flagged = [i for i, row in enumerate(rows) if row["predicted"] != BENIGN or row["outlier"]]
    for i, row in enumerate(rows):
        row["flow_id"] = hashlib.sha256(f"{sensor_session}:{batch_id}:{checksum}:{i}".encode()).hexdigest()[:32]
        row["mode"], row["sensor_session"] = "local_sensor", sensor_session
    for a, i in zip(new_alerts, flagged):
        a.update(alert_id=rows[i]["flow_id"], flow_id=rows[i]["flow_id"],
                 dst=rows[i].get("dst"), dport=rows[i].get("dport"),
                 mode="local_sensor", sensor_session=sensor_session,
                 values={e["feature"]: e["value"] for e in a["explanation"]})
    now = datetime.now(timezone.utc).isoformat()
    with _sensor_lock:
        # A concurrent retry may have finished scoring; accept each batch only once.
        previous = next((b for b in _sensor["batches"] if b["key"] == batch_key), None)
        if previous:
            if previous["checksum"] != checksum:
                raise HTTPException(status_code=409, detail="batch_id reused with different data")
            return {**previous["result"], "duplicate": True}
        for row in rows:
            _sensor["seq"] += 1
            row["seq"] = _sensor["seq"]
        for a, i in zip(new_alerts, flagged):
            a["seq"] = rows[i]["seq"]
        prior = _sensor["summary"] or {}
        result = {"mode": "local_sensor", "source": "sensor-submitted observations",
                  "sensor_session": sensor_session, "batch_id": batch_id, "rows": len(rows),
                  "alerts": len(new_alerts), "duplicate": False}
        _sensor["rows"] = (_sensor["rows"] + rows)[-MAX_SENSOR_KEPT:]
        _sensor["alerts"] = (_sensor["alerts"] + new_alerts)[-MAX_SENSOR_KEPT:]
        _sensor["summary"] = {**result, "sensor_id": _private_host(sensor_id), "received_at": now,
                              "total_flows": prior.get("total_flows", 0) + len(rows),
                              "total_alerts": prior.get("total_alerts", 0) + len(new_alerts),
                              "predicted_counts": flows["predicted"].value_counts().to_dict(),
                              "outliers": int(flows["outlier"].sum()),
                              "demoted": prior.get("demoted", 0) + int(flows["demoted"].sum()),
                              "reported_capture": stats,
                              "ground_truth_available": False, "addresses_pseudonymised": True,
                              "model": state()["mode"]}
        _sensor["batches"] = (_sensor["batches"] + [{"key": batch_key, "checksum": checksum, "result": result}])[-128:]
        _state["alerts"] = (_state["alerts"] + new_alerts)[-MAX_KEPT_ALERTS:]
        _remember(new_alerts, numeric, flagged)
        return result


@app.get("/sensor/feed", dependencies=[Depends(require_key)])
def sensor_feed(after: int = 0, limit: int = 100):
    """Bounded incremental observations; no accuracy/precision/recall for unlabelled traffic."""
    after, limit = max(0, after), max(1, min(limit, 200))
    with _sensor_lock:
        rows = [r for r in _sensor["rows"] if r["seq"] > after][:limit]
        cursor = rows[-1]["seq"] if rows else _sensor["seq"]
        alerts = [a for a in _sensor["alerts"] if after < a["seq"] <= cursor][:limit]
        first = _sensor["rows"][0]["seq"] if _sensor["rows"] else 0
        return {"mode": "local_sensor", "connected": _sensor["summary"] is not None,
                "key_required": bool(API_KEY), "cursor": cursor, "latest_cursor": _sensor["seq"],
                "history_truncated": bool(first and after < first - 1),
                "flows": rows, "alerts": alerts, "summary": _sensor["summary"],
                "notice": "Candidate alerts; model needs local validation. Sender provenance is self-reported."}


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


@app.post("/score-csv", dependencies=[Depends(require_key)])
async def score_csv(file: UploadFile = File(...)):
    """Score an uploaded CICFlowMeter CSV. If it has a Label column, return a full evaluation too."""
    raw = await file.read(MAX_UPLOAD_MB * 1024 * 1024 + 1)  # never buffer more than the limit
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
    dupes = sorted({c for c in df.columns[df.columns.duplicated()] if c in det.features})
    if dupes:
        raise HTTPException(status_code=422, detail=f"ambiguous duplicate feature columns: {dupes[:6]}")
    # Same policy as training (ids.data.clean): rows with non-numeric, NaN or infinite features are dropped.
    X = df[det.features].apply(pd.to_numeric, errors="coerce")
    valid = np.isfinite(X.to_numpy(dtype=float)).all(axis=1)
    df = df[valid].reset_index(drop=True)
    if df.empty:
        raise HTTPException(status_code=422, detail="CSV contains no flow rows with valid feature values")
    flows, alerts = score_frame(det, state()["explainer"], df)
    out = {"rows": len(df), "dropped_invalid_rows": int((~valid).sum()), "alerts": len(alerts),
           "predicted_counts": flows["predicted"].value_counts().to_dict(),
           "outliers": int(flows["outlier"].sum()),
           "top_alerts": representative(alerts, MAX_RETURNED_ALERTS),
           "incidents": aggregate(alerts)[:100]}
    if "truth" in flows:
        rep = report(flows["truth"], flows["predicted"])
        fpr = rep["benign_fpr"]  # undefined (NaN) for attack-only files; JSON has no NaN
        out["evaluation"] = {"macro": rep["macro"], "benign_fpr": fpr if np.isfinite(fpr) else None,
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
    scored, alerts = score_frame(det, state()["explainer"], df)
    _state["alerts"] = (_state["alerts"] + alerts)[-MAX_KEPT_ALERTS:]  # bounded memory in long-running workers
    flagged = [i for i in range(len(scored)) if scored["predicted"].iat[i] != BENIGN or scored["outlier"].iat[i]]
    _remember(alerts, df, flagged)
    return {"scored": len(df), "alerts": alerts}


@app.get("/alerts", dependencies=[Depends(require_key)])
def alerts(limit: int = 200):
    return _state["alerts"][-limit:]


@app.get("/incidents", dependencies=[Depends(require_key)])
def incidents(window_minutes: int = 10):
    return aggregate(_state["alerts"], window_minutes)


@app.post("/alerts/{alert_id}/status", dependencies=[Depends(require_key)])
def set_status(alert_id: str, status: str):
    """Record a triage decision durably. Dismissing an alert confirms the flow was benign; it joins the repair
    set (see /triage/repair-set.csv) only if it resembles this site's normal traffic, because a few wrongly
    dismissed attacks can teach the retrained model to ignore their type (docs/RESEARCH.md, E10)."""
    if status not in STATUSES:
        raise HTTPException(status_code=422, detail="status must be open, confirmed or dismissed")
    for a in _state["alerts"]:
        if a["alert_id"] == alert_id:
            a["status"] = status
            features = _alert_features.get(alert_id)
            eligible = None
            if status == "dismissed" and features:
                check = getattr(detector(), "resembles_site_normal", None)
                inside = check(pd.DataFrame([features])) if check else None
                eligible = None if inside is None else bool(inside[0])
            triage().record(alert_id, status, a.get("predicted_class"), a.get("outlier"), features, eligible)
            return {**a, "repair_eligible": eligible}
    raise HTTPException(status_code=404, detail="alert not found")


@app.get("/triage/summary", dependencies=[Depends(require_key)])
def triage_summary():
    return triage().summary()


@app.get("/triage/repair-set.csv", dependencies=[Depends(require_key)])
def repair_set_csv():
    """Analyst-confirmed benign flows as a labelled CSV, the input to scripts/repair_model.py."""
    frame = triage().repair_set()
    return Response(frame.to_csv(index=False), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=repair_set.csv"})


@app.middleware("http")
async def revalidate_static(request, call_next):
    """Make browsers revalidate the console's files so a redeploy shows up on the next load."""
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-cache")
    return response


if WEB_DIR.exists():  # the web console; mounted last so API routes take precedence
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
