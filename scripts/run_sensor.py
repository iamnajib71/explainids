"""CLI for explicit passive capture, local conversion and loopback ingestion."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Also supports a source checkout before editable installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from ids import sensor  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]


def parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("doctor", "interfaces", "capture", "ingest"):
        p = sub.add_parser(name)
        if name != "ingest":
            p.add_argument("--capture-tool", help="explicit dumpcap/tshark executable; else PATH")
        if name in ("doctor", "capture"):
            p.add_argument("--converter-argv", help='trusted local JSON argv with {pcap} and {output}')
        if name != "interfaces":
            p.add_argument("--model-card", type=Path, default=ROOT / "models/model_card.json")
        if name in ("capture", "ingest"):
            p.add_argument("--push", action="store_true", help="submit only to the loopback API")
            p.add_argument("--api-url", default="http://127.0.0.1:8000/sensor/ingest")
            p.add_argument("--api-key-env", default="EXPLAINIDS_API_KEY")
            p.add_argument("--sensor-session", help="reuse this safe token to retry identical batches")
            p.add_argument("--sensor-id", help="optional short local sensor token, not a personal name")
        if name == "capture":
            p.add_argument("--interface", required=True)
            p.add_argument("--duration", type=int, required=True)
            p.add_argument("--max-bytes", type=int, required=True)
            p.add_argument("--converter-timeout", type=int, default=300)
        if name == "ingest":
            p.add_argument("csv", type=Path)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    folder: Path | None = None
    manifest: dict = {}
    try:
        if args.command in ("doctor", "interfaces"):
            tool = sensor.discover_tool(args.capture_tool)
            if args.command == "interfaces":
                if not tool:
                    raise sensor.SensorError("capture executable missing; supply --capture-tool")
                print(sensor.list_interfaces(tool))
                return 0
            card_ok = False
            try:
                count = len(sensor.load_features(args.model_card))
                card_ok = True
            except sensor.SensorError:
                count = 0
            converter = sensor.parse_converter(args.converter_argv) if args.converter_argv else None
            converter_tool = sensor.discover_tool(converter[0]) if converter else None
            result = {"capture_tool": tool, "model_card_available": card_ok, "feature_count": count,
                      "converter_executable": converter_tool,
                      "capture_performed": False, "driver_permissions_verified": False,
                      "converter_semantics_verified": False}
            print(json.dumps(result, indent=2))
            return 0 if tool and card_ok and converter_tool else 2

        features = sensor.load_features(args.model_card)
        template = None
        if args.command == "capture":
            if not args.converter_argv:
                raise sensor.SensorError("capture requires --converter-argv; no fabricated-feature fallback")
            template = sensor.parse_converter(args.converter_argv)
            tool = sensor.discover_tool(args.capture_tool)
            if not tool or not sensor.discover_tool(template[0]):
                raise sensor.SensorError("capture tool or converter executable missing; run doctor")
            # Validate all bounds before opening an interface.
            sensor.capture_argv(tool, args.interface, args.duration, args.max_bytes, Path("check.pcap"))
            if not 1 <= args.converter_timeout <= 3600:
                raise sensor.SensorError("converter timeout must be 1–3600 seconds")
        key = os.environ.get(args.api_key_env, "")
        if args.push:
            sensor.loopback_url(args.api_url)
            if not key:
                raise sensor.SensorError("API key environment variable missing; no upload performed")
        if args.sensor_session and not sensor.TOKEN.fullmatch(args.sensor_session):
            raise sensor.SensorError("invalid sensor-session token")
        if args.sensor_id and not sensor.TOKEN.fullmatch(args.sensor_id):
            raise sensor.SensorError("invalid sensor-id token")
        folder, manifest = sensor.new_session(ROOT / "data/sensor")
        manifest.update(model_card_sha256=sensor.digest(args.model_card), feature_count=len(features),
                        sensor_session=args.sensor_session or manifest["session_id"], mode=args.command)
        sensor.save_manifest(folder, manifest)
        if args.command == "capture":
            print("Passive capture: local packets may contain payloads and host identifiers. Keep this session private.")
            manifest.update(interface=args.interface, duration_limit_seconds=args.duration,
                            byte_limit=args.max_bytes, capture_tool=tool,
                            capture_tool_sha256=sensor.digest(Path(tool)),
                            capture_argv=sensor.capture_argv(tool, args.interface, args.duration,
                                                             args.max_bytes, folder / "capture.pcap"),
                            converter_argv=template,
                            converter_executable_sha256=sensor.digest(Path(sensor.discover_tool(template[0]))))
            sensor.save_manifest(folder, manifest)
            pcap = sensor.capture(tool, args.interface, args.duration, args.max_bytes, folder)
            manifest.update(capture_sha256=sensor.digest(pcap), capture_bytes=pcap.stat().st_size)
            sensor.save_manifest(folder, manifest)
            source = sensor.convert(pcap, template, folder, args.converter_timeout)
        else:
            source = args.csv.resolve()
        manifest.update(input_csv_sha256=sensor.digest(source))
        validated = folder / "validated.csv"
        rows, dropped = sensor.validate_csv(source, validated, features)
        manifest.update(rows=rows, dropped_unusable_rows=dropped,
                        validated_sha256=sensor.digest(validated), status="validated")
        sensor.save_manifest(folder, manifest)
        if args.push:
            for index, (count, payload) in enumerate(sensor.csv_batches(validated)):
                batch = f"b{index:06d}"
                ack = sensor.push_batch(args.api_url, key, payload, manifest["sensor_session"], batch, args.sensor_id)
                manifest["uploads"].append({"batch_id": batch, "rows": count, "ack": ack})
                sensor.save_manifest(folder, manifest)
            manifest["status"] = "submitted"
            sensor.save_manifest(folder, manifest)
        print(json.dumps({"session": str(folder), "rows": rows, "status": manifest["status"]}))
        return 0
    except (sensor.SensorError, OSError) as exc:
        if folder is not None:
            manifest.update(status="failed", error=str(exc))
            sensor.save_manifest(folder, manifest)
        print(f"Sensor error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
