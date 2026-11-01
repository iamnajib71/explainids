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
    assert store.summary() == {"decisions": {"confirmed": 1, "dismissed": 2, "open": 0}, "repair_set_flows": 1}


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
