import io
import os
import tempfile

os.environ["EXPLAINIDS_MODEL_DIR"] = tempfile.mkdtemp()  # hermetic: always the synthetic demo model

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
