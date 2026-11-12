"""The local entry point must not silently expose a server or start capture."""
from pathlib import Path
import json
import types

import pytest

from scripts import run_app


def test_doctor_reports_missing_layout_and_does_not_start_server(tmp_path, monkeypatch):
    monkeypatch.setattr(run_app.importlib.util, "find_spec", lambda name: None if name == "fastapi" else object())
    status = run_app.readiness(tmp_path / "models", root=tmp_path)
    assert not status["ready"]
    assert status["missing_dependencies"] == ["fastapi"]
    assert "api/main.py" in status["missing_files"]
    assert status["bind"] == "127.0.0.1" and status["capture_started"] is False


def test_model_folder_precedence_preserves_explicit_configuration(tmp_path, monkeypatch):
    configured = tmp_path / "configured"
    explicit = tmp_path / "explicit"
    monkeypatch.setenv("EXPLAINIDS_MODEL_DIR", str(configured))
    assert run_app.model_directory(None, root=tmp_path) == configured
    assert run_app.model_directory(str(explicit), root=tmp_path) == explicit
    monkeypatch.delenv("EXPLAINIDS_MODEL_DIR")
    assert run_app.model_directory(None, root=tmp_path) == tmp_path / "models"


@pytest.mark.parametrize("port", ["0", "65536", "not-a-number"])
def test_invalid_port_is_rejected_before_startup(port):
    with pytest.raises(SystemExit) as error:
        run_app.main(["--port", port])
    assert error.value.code == 2


def test_check_mode_never_constructs_a_server(monkeypatch, capsys):
    monkeypatch.setattr(run_app, "readiness", lambda folder: {"ready": True, "capture_started": False})
    assert run_app.main(["--check"]) == 0
    assert json.loads(capsys.readouterr().out) == {"ready": True, "capture_started": False}


def test_source_checkout_startup_is_loopback_only(monkeypatch, tmp_path):
    seen = {}

    class Config:
        def __init__(self, app, **kwargs):
            seen.update(app=app, **kwargs)

    class Server:
        def __init__(self, config):
            self.started = False

        def run(self):
            seen["ran"] = True

    monkeypatch.setattr(run_app, "readiness", lambda folder: {"ready": True})
    monkeypatch.setitem(run_app.sys.modules, "uvicorn", types.SimpleNamespace(Config=Config, Server=Server))
    monkeypatch.setattr(run_app.sys, "path", list(run_app.sys.path))
    monkeypatch.setenv("EXPLAINIDS_MODEL_DIR", str(tmp_path))
    assert run_app.main(["--no-browser", "--port", "8765"]) == 0
    assert seen == {"app": "api.main:app", "host": "127.0.0.1", "port": 8765, "log_level": "info", "ran": True}
