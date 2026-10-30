"""Time-sampled passive capture: repeated bounded sensor sessions with gaps between them.

One long capture on a busy link hits the byte bound in about a minute, and header-only capture
corrupts the extractor's features, so a deployment study instead samples the evening in blocks.
Each block is an ordinary `run_sensor.py capture` session with its own manifest; this script only
schedules them and records which sessions belong to the study.

  python scripts/capture_blocks.py --interface <npf-id> --converter-argv '<json>' \
      --blocks 12 --block-seconds 300 --gap-seconds 600 --study data/sensor/study_wifi.json

Capture only on a network you are authorised to monitor. It generates no traffic.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_BLOCKS = 48


def session_from_output(stdout: str) -> str | None:
    """The sensor prints one JSON line naming its session folder."""
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return Path(json.loads(line)["session"]).name
            except (ValueError, KeyError, TypeError):
                return None
    return None


def run_block(args: argparse.Namespace) -> dict:
    argv = [sys.executable, str(ROOT / "scripts/run_sensor.py"), "capture",
            "--interface", args.interface, "--duration", str(args.block_seconds),
            "--max-bytes", str(args.max_bytes), "--converter-argv", args.converter_argv,
            "--converter-timeout", str(args.converter_timeout)]
    started = datetime.now(timezone.utc).isoformat()
    proc = subprocess.run(argv, capture_output=True, text=True,
                          timeout=args.block_seconds + args.converter_timeout + 120, check=False)
    return {"started_utc": started, "returncode": proc.returncode,
            "session": session_from_output(proc.stdout), "error": proc.stderr.strip()[-300:] or None}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--interface", required=True)
    ap.add_argument("--converter-argv", required=True)
    ap.add_argument("--blocks", type=int, required=True)
    ap.add_argument("--block-seconds", type=int, default=300)
    ap.add_argument("--gap-seconds", type=int, default=600)
    ap.add_argument("--max-bytes", type=int, default=94_371_840)
    ap.add_argument("--converter-timeout", type=int, default=900)
    ap.add_argument("--study", type=Path, required=True, help="study record listing the block sessions")
    args = ap.parse_args(argv)
    if not 1 <= args.blocks <= MAX_BLOCKS:
        ap.error(f"--blocks must be 1–{MAX_BLOCKS}")
    if args.gap_seconds < 0:
        ap.error("--gap-seconds must be non-negative")

    study = {"interface": args.interface, "block_seconds": args.block_seconds,
             "gap_seconds": args.gap_seconds, "max_bytes": args.max_bytes, "blocks": []}
    args.study.parent.mkdir(parents=True, exist_ok=True)
    for i in range(args.blocks):
        block = run_block(args)
        block["index"] = i
        study["blocks"].append(block)
        args.study.write_text(json.dumps(study, indent=2), encoding="utf-8")
        print(json.dumps(block), flush=True)
        if i < args.blocks - 1:
            time.sleep(args.gap_seconds)
    ok = sum(b["returncode"] == 0 and b["session"] is not None for b in study["blocks"])
    print(f"{ok}/{args.blocks} blocks validated", flush=True)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
