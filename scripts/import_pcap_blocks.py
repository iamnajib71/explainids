"""Turn block captures made elsewhere into validated sensor sessions and a study record.

For a second network captured with `scripts/capture_pcap_blocks.ps1` (Wireshark only, no project install):

  python scripts/import_pcap_blocks.py <folder with block_XX.pcap and blocks.json> \
      --converter-argv '<json>' --study data/sensor/study_net2_<date>.json --discard-pcap

Each block becomes an ordinary session (`validated.csv`, `manifest.json`) exactly as `capture_blocks.py` would
have produced, so `real_network_eval.py` runs on it unchanged. `--discard-pcap` deletes each raw capture once
its flows validate, keeping only its hash: another household's packets are not retained.
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from ids import sensor  # noqa: E402


def import_block(pcap: Path, started: str | None, converter: list[str], features: list[str],
                 data_root: Path, discard: bool) -> dict:
    folder, manifest = sensor.new_session(data_root)
    manifest.update(mode="import", source_file=pcap.name, capture_started_utc=started,
                    pcap_sha256=sensor.digest(pcap), converter_argv=converter)
    try:
        local = folder / "capture.pcap"
        shutil.copyfile(pcap, local)
        csv = sensor.convert(local, converter, folder)
        kept, dropped = sensor.validate_csv(csv, folder / "validated.csv", features)
        manifest.update(status="validated", rows=kept, dropped_rows=dropped)
        if discard:
            local.unlink()
            pcap.unlink()
            manifest["raw_capture"] = "discarded after validation"
        return_code = 0
    except sensor.SensorError as exc:
        manifest.update(status="failed", error=str(exc))
        return_code = 1
    sensor.save_manifest(folder, manifest)
    return {"started_utc": started, "returncode": return_code, "session": folder.name,
            "error": manifest.get("error")}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--converter-argv", required=True)
    ap.add_argument("--study", type=Path, required=True)
    ap.add_argument("--model-card", type=Path, default=ROOT / "models/model_card.json")
    ap.add_argument("--discard-pcap", action="store_true")
    args = ap.parse_args(argv)

    converter = sensor.parse_converter(args.converter_argv)
    features = sensor.load_features(args.model_card)
    meta_file = args.folder / "blocks.json"
    meta = json.loads(meta_file.read_text(encoding="utf-8-sig")) if meta_file.is_file() else {"blocks": []}
    started = {b["file"]: b.get("started_utc") for b in meta.get("blocks", [])}
    pcaps = sorted(args.folder.glob("block_*.pcap"))
    if not pcaps:
        ap.error("no block_*.pcap files in the folder")

    study = {"imported_from": "capture_pcap_blocks.ps1", "interface": meta.get("interface"),
             "block_seconds": meta.get("block_seconds"), "gap_seconds": meta.get("gap_seconds"),
             "max_bytes": meta.get("max_bytes"), "blocks": []}
    args.study.parent.mkdir(parents=True, exist_ok=True)
    for i, pcap in enumerate(pcaps):
        block = import_block(pcap, started.get(pcap.name), converter, features, args.study.parent,
                             args.discard_pcap)
        block["index"] = i
        study["blocks"].append(block)
        args.study.write_text(json.dumps(study, indent=2), encoding="utf-8")
        print(json.dumps(block), flush=True)
    ok = sum(b["returncode"] == 0 for b in study["blocks"])
    print(f"{ok}/{len(pcaps)} blocks validated", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
