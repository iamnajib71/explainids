"""Windows-to-WSL bridge for the corrected CICFlowMeter extractor.

Usage (directly):
  python scripts/wsl_convert.py <capture.pcap> <output_dir> [--distro Ubuntu-24.04] [--timeout 900]

Usage (as the sensor's trusted converter, which substitutes Windows paths):
  --converter-argv "[\\"<python>\\", \\"scripts/wsl_convert.py\\", \\"{pcap}\\", \\"{output}\\"]"

The corrected extractor is built inside a WSL distribution (see `data/lab/tools/EXTRACTOR_SETUP.md`)
and only understands WSL paths, while `ids.sensor` substitutes resolved Windows paths into the
converter argv. This script translates both arguments and invokes the extractor through `wsl.exe`
with `shell=False`, a timeout and captured logs. It performs no capture and generates no traffic.

Path translation covers local drives only: `H:\\dir\\file` becomes `/mnt/h/dir/file`. UNC paths are
rejected because the extractor cannot reach them reliably. A schema match between the emitted CSV and
the model card is checked by the sensor, not here; this script only guarantees that exactly one
nonempty CSV was produced.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path, PureWindowsPath

EXTRACTOR = Path(__file__).resolve().parent.parent / "data" / "lab" / "tools" / "run_extractor.sh"
MAX_CSV_BYTES = 100 * 1024 * 1024


class BridgeError(RuntimeError):
    """A prerequisite is missing or the extractor did not produce one usable CSV."""


def to_wsl_path(windows_path: str | Path) -> str:
    """Translate an absolute local Windows path to its /mnt/<drive> equivalent."""
    pure = PureWindowsPath(windows_path)
    if pure.drive.startswith("\\\\") or str(windows_path).startswith("\\\\"):
        raise BridgeError(f"UNC paths are not supported by the extractor: {windows_path}")
    if not pure.drive or not pure.is_absolute():
        raise BridgeError(f"an absolute Windows path is required, got {windows_path!r}")
    drive = pure.drive.rstrip(":").lower()
    if len(drive) != 1 or not drive.isalpha():
        raise BridgeError(f"unexpected drive in {windows_path!r}")
    parts = [p for p in pure.parts[1:] if p not in ("\\", "/")]
    return "/".join([f"/mnt/{drive}", *parts]) if parts else f"/mnt/{drive}"


def distro_available(distro: str, timeout: int = 60) -> bool:
    """True when wsl.exe reports the named distribution."""
    try:
        proc = subprocess.run(["wsl.exe", "-l", "-q"], capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return False
    listed = proc.stdout.decode("utf-16-le", errors="ignore").replace("\x00", "")
    return any(line.strip() == distro for line in listed.splitlines())


def convert(pcap: Path, output: Path, distro: str, timeout: int, log: Path | None = None) -> Path:
    """Run the WSL extractor on one capture and return the single CSV it emitted."""
    if not pcap.is_file() or pcap.stat().st_size == 0:
        raise BridgeError(f"capture missing or empty: {pcap}")
    if not EXTRACTOR.is_file():
        raise BridgeError(f"extractor launcher not found: {EXTRACTOR}. See data/lab/tools/EXTRACTOR_SETUP.md")
    if not distro_available(distro):
        raise BridgeError(f"WSL distribution {distro!r} is not available")
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise BridgeError(f"output directory must be empty: {output}")

    argv = ["wsl.exe", "-d", distro, "--", "bash", to_wsl_path(EXTRACTOR),
            to_wsl_path(pcap.resolve()), to_wsl_path(output.resolve())]
    proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    if log is not None:
        log.write_bytes(b"$ " + " ".join(argv).encode() + b"\n" + proc.stdout + proc.stderr)
    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout).decode(errors="replace").strip().splitlines()[-5:]
        raise BridgeError(f"extractor exited {proc.returncode}: " + " | ".join(tail))

    produced = [p for p in sorted(output.glob("*.csv")) if p.stat().st_size > 0]
    if len(produced) != 1:
        raise BridgeError(f"expected exactly one nonempty CSV, found {len(produced)}")
    if produced[0].stat().st_size > MAX_CSV_BYTES:
        raise BridgeError(f"converted CSV exceeds {MAX_CSV_BYTES // (1024 * 1024)} MiB")
    return produced[0]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("pcap")
    ap.add_argument("output")
    ap.add_argument("--distro", default="Ubuntu-24.04")
    ap.add_argument("--timeout", type=int, default=900)
    args = ap.parse_args()
    try:
        csv = convert(Path(args.pcap), Path(args.output), args.distro, args.timeout)
    except BridgeError as exc:
        print(f"conversion failed: {exc}", file=sys.stderr)
        return 1
    print(csv)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
