import pandas as pd
import pytest

from scripts.score_capture import scope, service_name, summarise


@pytest.mark.parametrize("port,proto,expected", [
    (443, 6, "HTTPS"), (1900, 17, "SSDP"), (88, 6, "Kerberos"), (389, 17, "LDAP"),
    (0, 1, "ICMP"), (51234, 6, "ephemeral"), (3013, 6, "port-3013"), ("bad", 6, "unknown"),
])
def test_service_names(port, proto, expected):
    assert service_name(port, proto) == expected


@pytest.mark.parametrize("address,expected", [
    ("192.168.0.7", "internal"), ("10.1.2.3", "internal"), ("fe80::1", "internal"),
    ("239.255.255.250", "multicast"), ("150.171.109.145", "external"), ("not-an-ip", "unknown"),
])
def test_scope_never_returns_the_address(address, expected):
    assert scope(address) == expected


def test_summary_reports_burden_with_interval_and_service_breakdown():
    table = pd.DataFrame({
        "time": ["2026-10-29 13:00:00", "2026-10-29 13:30:00", "2026-10-29 14:00:00", "2026-10-29 14:00:00"],
        "service": ["SSDP", "SSDP", "HTTPS", "HTTPS"],
        "dst_scope": ["multicast", "multicast", "external", "external"],
        "predicted": ["PortScan", "BENIGN", "BENIGN", "BENIGN"],
        "alert": [True, False, False, True],
        "technique": ["T1046", "", "", ""],
    })
    s = summarise(table)
    assert s["flows"] == 4 and s["alerts"] == 2 and s["alert_rate"] == 0.5
    lo, hi = s["alert_rate_ci"]
    assert lo < 0.5 < hi
    assert s["observed_hours"] == 1.0 and s["alerts_per_hour"] == 2.0
    assert s["anomaly_only"] == 1                       # alerted while predicted BENIGN
    rates = {r["service"]: r["rate"] for r in s["by_service"]}
    assert rates == {"SSDP": 0.5, "HTTPS": 0.5}


def test_pseudonymisation_needs_a_private_key(monkeypatch):
    from ids.privacy import pseudonymise_value
    monkeypatch.delenv("EXPLAINIDS_PSEUDO_KEY", raising=False)
    with pytest.raises(RuntimeError, match="EXPLAINIDS_PSEUDO_KEY"):
        pseudonymise_value("192.168.0.7")
    monkeypatch.setenv("EXPLAINIDS_PSEUDO_KEY", "k")
    token = pseudonymise_value("192.168.0.7")
    assert token.startswith("host-") and "192" not in token
