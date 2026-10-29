import subprocess
from pathlib import Path

import pytest

from scripts import wsl_convert
from scripts.wsl_convert import BridgeError, convert, to_wsl_path


def test_translates_drive_letter_and_separators():
    assert to_wsl_path(r"H:\dir\file.pcap") == "/mnt/h/dir/file.pcap"
    assert to_wsl_path(r"C:\Users\x\y.pcap") == "/mnt/c/Users/x/y.pcap"
    assert to_wsl_path("H:\\") == "/mnt/h"


def test_preserves_spaces_and_matches_the_built_extractor_prefix():
    translated = to_wsl_path(r"H:\My Projects - IT\AI-Based Cybersecurity\data\x.pcap")
    assert translated == "/mnt/h/My Projects - IT/AI-Based Cybersecurity/data/x.pcap"
    # The launcher built in WSL hard-codes the same convention; a mismatch would break conversion.
    launcher = Path(wsl_convert.EXTRACTOR)
    if launcher.is_file():
        repo_in_wsl = to_wsl_path(launcher.parent.parent.parent.parent)
        assert repo_in_wsl.startswith("/mnt/")
        assert repo_in_wsl in launcher.read_text(encoding="utf-8"), (
            "run_extractor.sh must cd into the same /mnt path this bridge translates to")


@pytest.mark.parametrize("bad", [r"\\server\share\x.pcap", "relative/path.pcap", "x.pcap"])
def test_rejects_unc_and_relative_paths(bad):
    with pytest.raises(BridgeError):
        to_wsl_path(bad)


def capture(tmp_path: Path, size: int = 24) -> Path:
    pcap = tmp_path / "c.pcap"
    pcap.write_bytes(b"\0" * size)
    return pcap


def test_rejects_missing_or_empty_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(wsl_convert, "distro_available", lambda *a, **k: True)
    with pytest.raises(BridgeError, match="missing or empty"):
        convert(tmp_path / "absent.pcap", tmp_path / "out", "D", 10)
    empty = tmp_path / "e.pcap"
    empty.write_bytes(b"")
    with pytest.raises(BridgeError, match="missing or empty"):
        convert(empty, tmp_path / "out2", "D", 10)


def test_reports_a_missing_distribution_rather_than_running(tmp_path, monkeypatch):
    monkeypatch.setattr(wsl_convert, "distro_available", lambda *a, **k: False)
    monkeypatch.setattr(wsl_convert, "EXTRACTOR", tmp_path / "run.sh")
    (tmp_path / "run.sh").write_text("#!/bin/bash\n")
    with pytest.raises(BridgeError, match="not available"):
        convert(capture(tmp_path), tmp_path / "out", "Nope", 10)


def test_refuses_to_write_into_a_populated_output_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(wsl_convert, "distro_available", lambda *a, **k: True)
    monkeypatch.setattr(wsl_convert, "EXTRACTOR", tmp_path / "run.sh")
    (tmp_path / "run.sh").write_text("#!/bin/bash\n")
    out = tmp_path / "out"
    out.mkdir()
    (out / "existing.csv").write_text("stale\n")
    with pytest.raises(BridgeError, match="must be empty"):
        convert(capture(tmp_path), out, "D", 10)


def run_with(monkeypatch, tmp_path, emit, returncode=0):
    """Install a fake wsl.exe that writes `emit` files into the output directory."""
    monkeypatch.setattr(wsl_convert, "distro_available", lambda *a, **k: True)
    monkeypatch.setattr(wsl_convert, "EXTRACTOR", tmp_path / "run.sh")
    (tmp_path / "run.sh").write_text("#!/bin/bash\n")

    def fake_run(argv, **kwargs):
        assert argv[0] == "wsl.exe" and "--" in argv, "must invoke wsl.exe without a shell"
        assert all(not a.startswith(("H:", "C:")) for a in argv[-2:]), "paths must be translated"
        for name, content in emit.items():
            (tmp_path / "out" / name).write_text(content)
        return subprocess.CompletedProcess(argv, returncode, b"out", b"err")

    monkeypatch.setattr(subprocess, "run", fake_run)
    return tmp_path / "out"


def test_returns_the_single_csv_on_success(tmp_path, monkeypatch):
    out = run_with(monkeypatch, tmp_path, {"flows.csv": "a,b\n1,2\n"})
    result = convert(capture(tmp_path), out, "D", 10, log=tmp_path / "log.txt")
    assert result.name == "flows.csv"
    assert "wsl.exe" in (tmp_path / "log.txt").read_text()


def test_rejects_zero_or_multiple_csv_outputs(tmp_path, monkeypatch):
    out = run_with(monkeypatch, tmp_path, {"a.csv": "x\n", "b.csv": "y\n"})
    with pytest.raises(BridgeError, match="exactly one"):
        convert(capture(tmp_path), out, "D", 10)


def test_empty_csv_does_not_count_as_a_result(tmp_path, monkeypatch):
    out = run_with(monkeypatch, tmp_path, {"flows.csv": ""})
    with pytest.raises(BridgeError, match="exactly one"):
        convert(capture(tmp_path), out, "D", 10)


def test_surfaces_extractor_failure_with_its_output(tmp_path, monkeypatch):
    out = run_with(monkeypatch, tmp_path, {}, returncode=3)
    with pytest.raises(BridgeError, match="exited 3"):
        convert(capture(tmp_path), out, "D", 10)
