import json
import sys

import scripts.import_pcap_blocks as imp

CONVERTER = ("import pathlib,sys\nassert pathlib.Path(sys.argv[1]).exists()\n"
             "pathlib.Path(sys.argv[2], 'flows.csv').write_text('f1,f2,Label\\n1,2,x\\n3,inf,x\\n')\n")


def _setup(tmp_path, broken=False):
    folder = tmp_path / "net2"
    folder.mkdir()
    for i in range(2):
        (folder / f"block_{i:02d}.pcap").write_bytes(b"fixture" if not (broken and i) else b"")
    (folder / "blocks.json").write_text(json.dumps({"interface": "4", "block_seconds": 300, "gap_seconds": 600,
        "blocks": [{"file": "block_00.pcap", "started_utc": "2026-11-08T09:00:00Z"}]}), encoding="utf-8")
    card = tmp_path / "card.json"
    card.write_text(json.dumps({"features": ["f1", "f2"]}), encoding="utf-8")
    script = tmp_path / "conv.py"
    script.write_text(CONVERTER)
    return folder, card, json.dumps([sys.executable, str(script), "{pcap}", "{output}"])


def test_blocks_become_validated_sessions_in_a_study_record(tmp_path):
    folder, card, conv = _setup(tmp_path)
    study = tmp_path / "sensor" / "study_net2.json"
    assert imp.main([str(folder), "--converter-argv", conv, "--study", str(study), "--model-card", str(card),
                     "--discard-pcap"]) == 0
    record = json.loads(study.read_text())
    assert [b["returncode"] for b in record["blocks"]] == [0, 0]
    assert record["blocks"][0]["started_utc"] == "2026-11-08T09:00:00Z" and record["interface"] == "4"
    session = study.parent / record["blocks"][0]["session"]
    assert (session / "validated.csv").read_text().splitlines()[0] == "f1,f2", "labels are stripped"
    manifest = json.loads((session / "manifest.json").read_text())
    assert manifest["rows"] == 1 and manifest["dropped_rows"] == 1 and len(manifest["pcap_sha256"]) == 64
    assert not (session / "capture.pcap").exists() and not list(folder.glob("*.pcap")), "raw captures discarded"


def test_a_failed_block_is_recorded_and_its_raw_capture_kept(tmp_path):
    folder, card, conv = _setup(tmp_path, broken=True)
    study = tmp_path / "sensor" / "study_net2.json"
    assert imp.main([str(folder), "--converter-argv", conv, "--study", str(study), "--model-card", str(card),
                     "--discard-pcap"]) == 0
    blocks = json.loads(study.read_text())["blocks"]
    assert [b["returncode"] for b in blocks] == [0, 1] and blocks[1]["error"]
    assert (folder / "block_01.pcap").exists()
