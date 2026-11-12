import pytest

from ids.triage_store import TriageStore


def test_dismissed_alerts_with_features_become_the_repair_set(tmp_path):
    store = TriageStore(tmp_path / "triage.sqlite")
    store.record("a1", "dismissed", "PortScan", False, {"Flow Duration": 10.0, "Dst Port": 1900})
    store.record("a2", "confirmed", "DoS-Hulk", False, {"Flow Duration": 5.0, "Dst Port": 80})
    store.record("a3", "dismissed", "BENIGN", True, None)          # no features: cannot be used
    repair = store.repair_set()
    assert list(repair["alert_id"]) == ["a1"]
    assert repair.loc[0, "Label"] == "BENIGN" and repair.loc[0, "model_said"] == "PortScan"
    assert store.summary() == {"decisions": {"confirmed": 1, "dismissed": 2, "open": 0}, "repair_set_flows": 1,
                               "held_back": 0, "ungated": 1}


def test_decisions_survive_reopening_and_keep_first_features(tmp_path):
    path = tmp_path / "triage.sqlite"
    TriageStore(path).record("a1", "dismissed", "PortScan", False, {"x": 1.0})
    store = TriageStore(path)
    store.record("a1", "open")                       # analyst reopens; features are not lost
    assert store.status("a1") == "open"
    store.record("a1", "dismissed")
    assert store.repair_set().loc[0, "x"] == 1.0


def test_unknown_status_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        TriageStore(tmp_path / "t.sqlite").record("a1", "deleted")


def test_dismissals_outside_site_normal_are_held_back(tmp_path):
    store = TriageStore(tmp_path / "triage.sqlite")
    store.record("ok", "dismissed", "PortScan", False, {"x": 1.0}, repair_eligible=True)
    store.record("odd", "dismissed", "PortScan", False, {"x": 9.0}, repair_eligible=False)
    assert list(store.repair_set()["alert_id"]) == ["ok"]
    assert store.summary()["held_back"] == 1 and store.summary()["repair_set_flows"] == 1
    store.record("odd", "open")                       # reopening keeps the gate verdict
    store.record("odd", "dismissed")
    assert list(store.repair_set()["alert_id"]) == ["ok"]


def test_store_made_before_the_gate_is_migrated(tmp_path):
    import sqlite3
    path = tmp_path / "old.sqlite"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE decisions (alert_id TEXT PRIMARY KEY, status TEXT NOT NULL, decided_utc TEXT "
                   "NOT NULL, predicted_class TEXT, outlier INTEGER, features TEXT)")
        db.execute("INSERT INTO decisions VALUES ('a1', 'dismissed', '2026-01-01', 'PortScan', 0, '{\"x\": 1.0}')")
    store = TriageStore(path)
    assert list(store.repair_set()["alert_id"]) == ["a1"] and store.summary()["ungated"] == 1
