from fastapi.testclient import TestClient

from api.main import app
from ids.synthetic import make_flows

client = TestClient(app)


def test_health_reports_demo_model():
    r = client.get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_predict_returns_explained_alerts_and_status_update():
    flows = make_flows(5).drop(columns=["Label"]).to_dict("records")
    r = client.post("/predict", json={"flows": flows})
    assert r.status_code == 200
    alerts = r.json()["alerts"]
    assert alerts and {"attack", "severity", "summary", "status"} <= set(alerts[0])
    aid = alerts[0]["alert_id"]
    assert client.post(f"/alerts/{aid}/status", params={"status": "confirmed"}).json()["status"] == "confirmed"
    assert client.get("/incidents").json()


def test_predict_rejects_bad_input():
    assert client.post("/predict", json={"flows": []}).status_code == 422
    assert client.post("/predict", json={"flows": [{"foo": 1}]}).status_code == 422
