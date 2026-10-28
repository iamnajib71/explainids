"""Sensor tests use fixtures/mocks only; never access a capture interface."""
import csv
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from ids import sensor


def write_csv(path, rows, header=("f1", "f2", "Label", "Src IP")):
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def test_capture_has_explicit_interface_and_both_autostops(tmp_path):
    args = sensor.capture_argv("dumpcap", r"\Device\NPF_abc", 30, sensor.MIB, tmp_path / "a.pcap")
    assert args[args.index("-i") + 1] == r"\Device\NPF_abc"
    assert "duration:30" in args and "filesize:896" in args
    assert args[args.index("-F") + 1] == "pcap" and "-p" in args
    assert args[-1] == str(tmp_path / "a.pcap")


@pytest.mark.parametrize("interface", ["", "-", "-i eth0", "rpcap://example/a", "TCP@127.0.0.1:80", "a\nb"])
def test_no_implicit_remote_or_injected_capture_interface(interface, tmp_path):
    with pytest.raises(sensor.SensorError):
        sensor.capture_argv("dumpcap", interface, 30, sensor.MIB, tmp_path / "a")


@pytest.mark.parametrize("duration,size", [(0, sensor.MIB), (3601, sensor.MIB), (30, 10), (30, 101*sensor.MIB)])
def test_capture_bounds_fail_before_execution(duration, size, tmp_path):
    with pytest.raises(sensor.SensorError):
        sensor.capture_argv("dumpcap", "1", duration, size, tmp_path / "a")


def test_command_timeout_nonzero_and_no_shell(monkeypatch, tmp_path):
    def timeout(args, **kwargs):
        assert kwargs["shell"] is False and kwargs["timeout"] == 5
        raise subprocess.TimeoutExpired(args, 5)
    monkeypatch.setattr(sensor.subprocess, "run", timeout)
    with pytest.raises(sensor.SensorError, match="timed out"):
        sensor.run_command(["tool", "literal;not-a-shell"], 5, tmp_path / "timeout.log")
    monkeypatch.setattr(sensor.subprocess, "run", lambda *a, **kw: SimpleNamespace(returncode=7))
    with pytest.raises(sensor.SensorError, match="exited 7"):
        sensor.run_command(["tool"], 5, tmp_path / "bad.log")


def test_capture_rejects_oversized_output(monkeypatch, tmp_path):
    def oversized(argv, *_):
        Path(argv[-1]).write_bytes(b"x" * (sensor.MIB + 1))
    monkeypatch.setattr(sensor, "run_command", oversized)
    with pytest.raises(sensor.SensorError, match="byte budget"):
        sensor.capture("dumpcap", "1", 1, sensor.MIB, tmp_path)


@pytest.mark.parametrize("argv", ['"not an array"', '["tool","{pcap}"]', '["tool","{pcap}","{other}","{output}"]'])
def test_converter_rejects_missing_or_unknown_placeholders(argv):
    with pytest.raises(sensor.SensorError):
        sensor.parse_converter(argv)


def test_local_converter_adapter_uses_literal_argv_and_validates_result(tmp_path):
    # A tiny owned fixture converter, not a real packet extractor or feature substitute.
    script = tmp_path / "fixture converter.py"
    script.write_text("import pathlib,sys\nassert pathlib.Path(sys.argv[1]).exists()\n"
                      "pathlib.Path(sys.argv[2], 'flows.csv').write_text('f1,f2\\n1,2\\n')\n")
    pcap = tmp_path / "fixture.pcap"
    pcap.write_bytes(b"fixture")
    out = sensor.convert(pcap, [sys.executable, str(script), "{pcap}", "{output}"], tmp_path)
    assert sensor.validate_csv(out, tmp_path / "validated.csv", ["f1", "f2"]) == 1


def test_converter_requires_one_csv(monkeypatch, tmp_path):
    monkeypatch.setattr(sensor, "run_command", lambda *_: None)
    (tmp_path / "a").write_bytes(b"fixture")
    with pytest.raises(sensor.SensorError, match="exactly one"):
        sensor.convert(tmp_path / "a", [sys.executable, "{pcap}", "{output}"], tmp_path)


def test_validation_keeps_features_and_metadata_but_removes_truth(tmp_path):
    source = write_csv(tmp_path / "raw.csv", [[1, 2, "attack", "192.0.2.1"]])
    target = tmp_path / "validated.csv"
    assert sensor.validate_csv(source, target, ["f1", "f2"]) == 1
    text = target.read_text()
    assert "Label" not in text and "attack" not in text and "Src IP" in text
    assert sensor.digest(source) != sensor.digest(target)


@pytest.mark.parametrize("bad", ["", "nan", "inf", "-inf", "not-a-number"])
def test_invalid_feature_rejected_without_output(tmp_path, bad):
    source = write_csv(tmp_path / "raw.csv", [[bad, 2, "BENIGN", "x"]])
    target = tmp_path / "validated.csv"
    with pytest.raises(sensor.SensorError, match="nonfinite"):
        sensor.validate_csv(source, target, ["f1", "f2"])
    assert not target.exists()


@pytest.mark.parametrize("header,rows", [(("f1",), [[1]]), (("f1", " f1 "), [[1,2]]), (("f1", "f2"), [])])
def test_missing_duplicate_empty_schema_rejected(tmp_path, header, rows):
    source = write_csv(tmp_path / "raw.csv", rows, header)
    with pytest.raises(sensor.SensorError):
        sensor.validate_csv(source, tmp_path / "out.csv", ["f1", "f2"])


def test_existing_output_not_deleted_or_overwritten(tmp_path):
    source = write_csv(tmp_path / "raw.csv", [[1,2,"BENIGN","x"]])
    out = tmp_path / "out.csv"
    out.write_text("keep")
    with pytest.raises(sensor.SensorError, match="already exists"):
        sensor.validate_csv(source, out, ["f1", "f2"])
    assert out.read_text() == "keep"


def test_batching_bounds_rows_and_bytes(tmp_path, monkeypatch):
    source = write_csv(tmp_path / "raw.csv", [[i,2] for i in range(2005)], ("f1","f2"))
    batches = list(sensor.csv_batches(source))
    assert [n for n,_ in batches] == [1000,1000,5]
    assert all(len(b) <= 5*sensor.MIB for _,b in batches)
    monkeypatch.setattr(sensor, "MAX_BATCH_BYTES", 30)
    small = list(sensor.csv_batches(source))
    assert sum(n for n,_ in small) == 2005 and all(len(b)<=30 for _,b in small)


@pytest.mark.parametrize("url", ["http://localhost:8000/sensor/ingest", "http://192.168.1.1/sensor/ingest",
                                "http://127.0.0.1@evil.test/sensor/ingest", "http://127.0.0.1/sensor/ingest?q=x",
                                "ftp://127.0.0.1/sensor/ingest", "http://127.0.0.1/score-csv"])
def test_external_or_ambiguous_api_destinations_rejected(url):
    with pytest.raises(sensor.SensorError):
        sensor.loopback_url(url)


def test_multipart_uses_agreed_metadata_no_proxy_and_no_redirect(monkeypatch):
    class Response:
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def read(self, limit): return b'{"rows":1,"mode":"local_sensor"}'
    def open_request(req, timeout):
        assert req.full_url == "http://127.0.0.1:8000/sensor/ingest"
        assert req.headers["X-api-key"] == "local-secret" and timeout == 30
        assert b'name="sensor_session"' in req.data and b'name="batch_id"' in req.data
        assert b'name="file"' in req.data and b"local-secret" not in req.data
        return Response()
    def opener(*handlers):
        assert handlers[0].proxies == {} and isinstance(handlers[1], sensor._NoRedirect)
        assert handlers[1].redirect_request(None,None,302,"",{},"http://evil.test") is None
        return SimpleNamespace(open=open_request)
    monkeypatch.setattr(sensor.urllib.request,"build_opener",opener)
    result = sensor.push_batch("http://127.0.0.1:8000/sensor/ingest", "local-secret", b"f1\n1\n", "session", "b000000")
    assert result["rows"] == 1


def test_model_card_features_and_fresh_private_sessions(tmp_path):
    card = tmp_path / "model.json"
    card.write_text(json.dumps({"features":["f1","f2"]}))
    assert sensor.load_features(card) == ["f1","f2"]
    card.write_text(json.dumps({"features":["f1","f1"]}))
    with pytest.raises(sensor.SensorError): sensor.load_features(card)
    folder, manifest = sensor.new_session(tmp_path / "data/sensor")
    sensor.save_manifest(folder,manifest)
    assert folder.parent == tmp_path / "data/sensor"
    assert (folder / "manifest.json").is_file()


def test_interfaces_only_runs_listing_command(monkeypatch):
    def run(argv, **kwargs):
        assert argv == ["dumpcap", "-D"] and kwargs["shell"] is False
        return SimpleNamespace(returncode=0,stdout="1. test-interface\n")
    monkeypatch.setattr(sensor.subprocess,"run",run)
    assert "test-interface" in sensor.list_interfaces("dumpcap")


def test_cli_validates_whole_file_before_push_and_saves_each_batch(tmp_path, monkeypatch):
    from scripts import run_sensor
    monkeypatch.setattr(run_sensor, "ROOT", tmp_path)
    card = tmp_path / "card.json"
    card.write_text(json.dumps({"features":["f1","f2"]}))
    source = write_csv(tmp_path / "source.csv", [[i,2,"BENIGN","192.0.2.1"] for i in range(1001)])
    calls = []
    def push(url,key,payload,session,batch,sensor_id):
        assert key == "test-key" and b"Label" not in payload
        calls.append((session,batch))
        return {"rows":len(list(csv.reader(io.StringIO(payload.decode()))))-1,"duplicate":False}
    import io
    monkeypatch.setenv("EXPLAINIDS_API_KEY", "test-key")
    monkeypatch.setattr(sensor,"push_batch",push)
    assert run_sensor.main(["ingest",str(source),"--model-card",str(card),"--push","--sensor-session","retry_token"]) == 0
    assert calls == [("retry_token","b000000"),("retry_token","b000001")]
    manifests = list((tmp_path / "data/sensor").glob("*/manifest.json"))
    manifest = json.loads(manifests[0].read_text())
    assert manifest["status"] == "submitted" and manifest["rows"] == 1001
    assert len(manifest["uploads"]) == 2 and "test-key" not in manifests[0].read_text()
    calls.clear()
    bad = write_csv(tmp_path / "bad.csv", [[1,2,"BENIGN","x"],["nan",2,"BENIGN","x"]])
    assert run_sensor.main(["ingest",str(bad),"--model-card",str(card),"--push"]) == 2
    assert not calls


def test_cli_doctor_and_missing_interface_never_capture(tmp_path, monkeypatch):
    from scripts import run_sensor
    card = tmp_path / "card.json"
    card.write_text(json.dumps({"features":["f1"]}))
    monkeypatch.setattr(sensor,"discover_tool",lambda *_: None)
    monkeypatch.setattr(sensor,"capture",lambda *_: pytest.fail("capture must not start"))
    assert run_sensor.main(["doctor","--model-card",str(card)]) == 2
    with pytest.raises(SystemExit):
        run_sensor.main(["capture","--duration","30","--max-bytes",str(sensor.MIB)])
