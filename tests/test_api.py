import io
import os
import tempfile
import pytest

os.environ["EXPLAINIDS_MODEL_DIR"] = tempfile.mkdtemp()  # hermetic: always the synthetic demo model
os.environ["EXPLAINIDS_TRIAGE_DB"] = os.path.join(tempfile.mkdtemp(), "triage.sqlite")  # never the real store

from fastapi.testclient import TestClient  # noqa: E402

from api.main import app  # noqa: E402
from ids.synthetic import make_flows  # noqa: E402

client = TestClient(app)


def test_health_reports_demo_model():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"
    assert r.json()["replay_flows"] > 0


def test_predict_returns_explained_alerts_and_status_update():
    flows = make_flows(5).drop(columns=["Label"]).to_dict("records")
    r = client.post("/predict", json={"flows": flows})
    assert r.status_code == 200
    alerts = r.json()["alerts"]
    assert alerts and {"attack", "severity", "summary", "status"} <= set(alerts[0])
    assert all(a["explanation"] for a in alerts if not a["outlier"]), "every classifier alert carries SHAP features"
    aid = alerts[0]["alert_id"]
    assert client.post(f"/alerts/{aid}/status", params={"status": "confirmed"}).json()["status"] == "confirmed"
    assert client.get("/incidents").json()


def test_predict_rejects_bad_input():
    assert client.post("/predict", json={"flows": []}).status_code == 422
    assert client.post("/predict", json={"flows": [{"foo": 1}]}).status_code == 422


def test_replay_is_stateless_and_carries_ground_truth():
    a = client.get("/replay", params={"cursor": 0, "n": 50}).json()
    b = client.get("/replay", params={"cursor": 0, "n": 50}).json()
    assert a["cursor"] == 50 and len(a["flows"]) == 50
    assert [f["predicted"] for f in a["flows"]] == [f["predicted"] for f in b["flows"]]
    assert all("truth" in f for f in a["flows"])
    assert all(al["verdict"] in {"correct", "false positive", "attack, other class"} for al in a["alerts"])


def test_replay_wraps_at_the_end():
    total = client.get("/health").json()["replay_flows"]
    r = client.get("/replay", params={"cursor": total - 5, "n": 10}).json()
    assert r["wrapped"] and r["cursor"] == 5


def test_sample_csv_round_trips_through_upload_with_evaluation():
    csv = client.get("/sample.csv", params={"rows": 200}).content
    r = client.post("/score-csv", files={"file": ("flows.csv", io.BytesIO(csv), "text/csv")})
    assert r.status_code == 200
    body = r.json()
    assert body["rows"] == 200 and "evaluation" in body
    assert 0 <= body["evaluation"]["macro"]["f1"] <= 1


def test_upload_reports_missing_features():
    r = client.post("/score-csv", files={"file": ("x.csv", io.BytesIO(b"a,b\n1,2\n"), "text/csv")})
    assert r.status_code == 422 and "missing" in r.json()["detail"]


def test_model_card_and_web_console_are_served():
    assert "classes" in client.get("/model").json()
    page = client.get("/")
    assert page.status_code == 200 and "ExplainIDS" in page.text


def _upload(client, text: str):
    return client.post("/score-csv", files={"file": ("flows.csv", text.encode(), "text/csv")})


def test_score_csv_rejects_header_only_and_duplicate_columns():
    from api.main import detector
    header = ",".join(detector().features)
    assert _upload(client, header + "\n").status_code == 422
    dup = header + ",Flow_Duration\n" + ",".join(["1"] * (len(detector().features) + 1)) + "\n"
    assert _upload(client, dup).status_code == 422


def test_score_csv_skips_invalid_rows_and_handles_attack_only_labels():
    from api.main import detector
    feats = detector().features
    good = ",".join(["1"] * len(feats)) + ",PortScan"
    bad = ",".join(["inf"] + ["1"] * (len(feats) - 1)) + ",PortScan"
    r = _upload(client, ",".join(feats) + ",Label\n" + good + "\n" + bad + "\n")
    assert r.status_code == 200
    body = r.json()
    assert body["rows"] == 1 and body["dropped_invalid_rows"] == 1
    assert body["evaluation"]["benign_fpr"] is None


@pytest.fixture
def sensor_api(monkeypatch):
    import api.main as api
    # Hermetic feature/scoring fixture; tests do not assert a synthetic model is deployable.
    monkeypatch.setitem(api.state(), "mode", "trained on test fixture")
    monkeypatch.setattr(api, "_sensor", {"rows": [], "alerts": [], "seq": 0, "batches": [], "summary": None})
    monkeypatch.setattr(api, "API_KEY", None)
    return api


def sensor_upload(frame, **metadata):
    return client.post("/sensor/ingest", data=metadata,
                       files={"file": ("flows.csv", frame.to_csv(index=False).encode(), "text/csv")})


def test_sensor_auth_required_for_ingest_and_feed(sensor_api, monkeypatch):
    monkeypatch.setattr(sensor_api, "API_KEY", "test-secret")
    csv_bytes = make_flows(2).to_csv(index=False).encode()
    assert client.post("/sensor/ingest", files={"file": ("f.csv", csv_bytes)}).status_code == 401
    assert client.get("/sensor/feed").status_code == 401
    assert client.get("/sensor/feed", headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/sensor/feed", headers={"X-API-Key": "test-secret"}).json()["connected"] is False
    response = client.post("/sensor/ingest", headers={"X-API-Key": "test-secret"},
                           files={"file": ("f.csv", csv_bytes)})
    assert response.status_code == 200


def test_sensor_refuses_synthetic_model(sensor_api, monkeypatch):
    monkeypatch.setitem(sensor_api.state(), "mode", "demo (synthetic)")
    assert sensor_upload(make_flows(2)).status_code == 503
    assert client.get("/sensor/feed").json()["connected"] is False


def test_sensor_requires_complete_finite_schema_and_valid_timestamps(sensor_api):
    import pandas as pd
    assert sensor_upload(pd.DataFrame({"bad": [1]})).status_code == 422
    frame = make_flows(2)
    feature = sensor_api.detector().features[0]
    frame[feature] = frame[feature].astype(float)
    frame.loc[0, feature] = float("inf")
    assert sensor_upload(frame).status_code == 422
    frame = make_flows(2)
    frame["Timestamp"] = frame["Timestamp"].astype(str)
    frame.loc[0, "Timestamp"] = "not-a-time"
    assert sensor_upload(frame).status_code == 422
    assert client.get("/sensor/feed").json()["cursor"] == 0


def test_sensor_discards_supplied_truth_pseudonymises_and_retries_idempotently(sensor_api):
    frame = make_flows(5)
    response = sensor_upload(frame, sensor_session="session_1", batch_id="batch_1", sensor_id="private-pc")
    assert response.status_code == 200
    first = client.get("/sensor/feed", params={"limit": 200}).json()
    assert first["summary"]["total_flows"] == len(frame)
    assert first["summary"]["ground_truth_available"] is False
    assert first["summary"]["sensor_id"].startswith("host-")
    assert first["alerts"] and first["mode"] == "local_sensor"
    for row in first["flows"]:
        assert "truth" not in row and row["src"].startswith("host-") and row["dst"].startswith("host-")
        assert row["mode"] == "local_sensor"
    for alert in first["alerts"]:
        assert not {"truth", "verdict", "evaluation", "accuracy"} & alert.keys()
        assert alert["source"].startswith("host-") and alert["explanation"]
    assert not {"accuracy", "precision", "recall", "evaluation", "confusion"} & first["summary"].keys()
    retry = sensor_upload(frame, sensor_session="session_1", batch_id="batch_1")
    assert retry.json()["duplicate"] is True
    assert client.get("/sensor/feed").json()["summary"]["total_flows"] == len(frame)
    frame.loc[0, sensor_api.detector().features[0]] += 1
    assert sensor_upload(frame, sensor_session="session_1", batch_id="batch_1").status_code == 409


def test_sensor_rejects_oversized_rows_bytes_duplicate_columns_and_metadata(sensor_api, monkeypatch):
    frame = make_flows(2)
    monkeypatch.setattr(sensor_api, "MAX_SENSOR_ROWS", 1)
    assert sensor_upload(frame).status_code == 413
    monkeypatch.setattr(sensor_api, "MAX_SENSOR_ROWS", 1000)
    monkeypatch.setattr(sensor_api, "MAX_SENSOR_BYTES", 10)
    assert sensor_upload(frame).status_code == 413
    monkeypatch.setattr(sensor_api, "MAX_SENSOR_BYTES", 5 * 1024 * 1024)
    csv_text = frame.to_csv(index=False)
    header, rest = csv_text.split("\n", 1)
    duplicate = header + "," + header.split(",")[0] + "\n" + rest
    assert client.post("/sensor/ingest", files={"file": ("f.csv", duplicate.encode())}).status_code == 422
    assert sensor_upload(frame, sensor_session="bad/session").status_code == 422
    assert sensor_upload(frame, session_stats='{"captured_packets":-1}').status_code == 422


def test_sensor_feed_pages_and_caps_history_without_mixing_replay(sensor_api, monkeypatch):
    monkeypatch.setattr(sensor_api, "MAX_SENSOR_KEPT", 4)
    frame = make_flows(2)
    assert sensor_upload(frame).status_code == 200
    feed = client.get("/sensor/feed", params={"limit": 99999}).json()
    assert len(feed["flows"]) == 4 and len(feed["alerts"]) <= 4
    assert feed["history_truncated"]
    page = client.get("/sensor/feed", params={"limit": 1}).json()
    assert len(page["flows"]) == 1
    next_page = client.get("/sensor/feed", params={"after": page["cursor"], "limit": 1}).json()
    assert next_page["cursor"] > page["cursor"]
    empty = client.get("/sensor/feed", params={"after": feed["cursor"]}).json()
    assert empty["flows"] == [] and empty["alerts"] == []
    assert all("truth" in row for row in client.get("/replay", params={"n": 2}).json()["flows"])


def test_dismissed_alert_is_kept_durably_as_a_repair_flow(tmp_path, monkeypatch):
    import api.main as main
    monkeypatch.setattr(main, "TRIAGE_DB", tmp_path / "triage.sqlite")
    flows = make_flows(8).drop(columns=["Label"]).to_dict("records")
    alerts = client.post("/predict", json={"flows": flows}).json()["alerts"]
    assert alerts
    aid = alerts[0]["alert_id"]
    assert client.post(f"/alerts/{aid}/status", params={"status": "dismissed"}).json()["status"] == "dismissed"
    assert client.get("/triage/summary").json() == {"decisions": {"confirmed": 0, "dismissed": 1, "open": 0},
                                                     "repair_set_flows": 1}
    csv = client.get("/triage/repair-set.csv")
    assert csv.status_code == 200 and "BENIGN" in csv.text and aid in csv.text
    assert main.TriageStore(tmp_path / "triage.sqlite").status(aid) == "dismissed"   # survives a restart
