"""Bounded passive capture and strict local flow-converter adapter.

External capture/conversion tools are operator-supplied prerequisites. No traffic
is generated and no model features are invented. Network submission is loopback only.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import math
import os
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator, Sequence

MIB = 1024 * 1024
MAX_INPUT_BYTES = 100 * MIB
MAX_ROWS = 200_000
MAX_BATCH_BYTES = 5 * MIB
MAX_BATCH_ROWS = 1000
META_COLUMNS = ("Src IP", "Dst IP", "Timestamp")
TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class SensorError(ValueError):
    """A failed prerequisite, capture, conversion, validation or local upload."""


def digest(path: Path) -> str:
    """Stream a file hash without loading packet captures into memory."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            h.update(chunk)
    return h.hexdigest()


def standard_capture_locations() -> list[Path]:
    """Usual Windows install directories for Wireshark's capture tools.

    The installer does not add them to PATH, so a present tool is otherwise reported as missing.
    This only looks; it never installs, elevates or changes any system setting.
    """
    roots = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"),
             r"C:\Program Files", r"C:\Program Files (x86)"]
    return [Path(root) / "Wireshark" for root in dict.fromkeys(r for r in roots if r)]


def discover_tool(explicit: str | None = None) -> str | None:
    """Find an explicit capture executable, a PATH tool, or a standard install; never install one."""
    choices = [explicit] if explicit else ["dumpcap", "tshark"]
    for choice in choices:
        if not choice:
            continue
        found = shutil.which(choice)
        if found:
            return str(Path(found).resolve())
        path = Path(choice).expanduser()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path.resolve())
    if explicit:
        return None
    for folder in standard_capture_locations():
        for name in ("dumpcap.exe", "tshark.exe"):
            candidate = folder / name
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return str(candidate.resolve())
    return None


def load_features(card: Path) -> list[str]:
    """Read the frozen model's actual feature list, not an assumed generic schema."""
    try:
        obj = json.loads(card.read_text(encoding="utf-8"))
        features = obj.get("features")
    except (OSError, ValueError, AttributeError) as exc:
        raise SensorError("cannot read a valid model card") from exc
    if (not isinstance(features, list) or not features
            or any(not isinstance(f, str) or not f.strip() or f != f.strip() for f in features)
            or len(set(features)) != len(features)):
        raise SensorError("model card features must be nonempty unique names")
    return features


def parse_converter(value: str) -> list[str]:
    """Parse a trusted JSON argv array; no shell tokenisation or expansion."""
    try:
        argv = json.loads(value)
    except ValueError as exc:
        raise SensorError("converter argv must be a JSON string array") from exc
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(a, str) or not a or "\0" in a for a in argv)):
        raise SensorError("converter argv must be a nonempty JSON string array")
    joined = "\n".join(argv[1:])
    if "{pcap}" not in joined or "{output}" not in joined:
        raise SensorError("converter argv requires {pcap} and {output} arguments")
    if any("{" in a.replace("{pcap}", "").replace("{output}", "") or
           "}" in a.replace("{pcap}", "").replace("{output}", "") for a in argv):
        raise SensorError("unknown converter placeholder")
    if "{pcap}" in argv[0] or "{output}" in argv[0]:
        raise SensorError("converter executable cannot be a placeholder")
    return argv


def new_session(data_root: Path) -> tuple[Path, dict[str, Any]]:
    """Create a unique session below the explicitly supplied private data root."""
    root = data_root.expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    sid = uuid.uuid4().hex
    folder = root / sid
    folder.mkdir(exist_ok=False)
    return folder, {"session_id": sid, "created_utc": datetime.now(timezone.utc).isoformat(),
                    "status": "created", "uploads": []}


def save_manifest(folder: Path, manifest: dict[str, Any]) -> None:
    """Atomically retain progress, including successful batches before later failures."""
    tmp = folder / "manifest.tmp"
    tmp.write_text(json.dumps(manifest, indent=2, allow_nan=False), encoding="utf-8")
    tmp.replace(folder / "manifest.json")


def run_command(argv: Sequence[str], timeout: float, log: Path) -> None:
    """Run local tools without a shell, stream their logs to ignored storage."""
    if not math.isfinite(timeout) or timeout <= 0:
        raise SensorError("command timeout must be positive and finite")
    try:
        with log.open("wb") as stream:
            result = subprocess.run(list(argv), shell=False, stdout=stream,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
    except subprocess.TimeoutExpired as exc:
        raise SensorError(f"command timed out; inspect {log.name}") from exc
    except OSError as exc:
        raise SensorError(f"cannot start local tool; inspect {log.name}") from exc
    if result.returncode:
        raise SensorError(f"local tool exited {result.returncode}; inspect {log.name}")


def list_interfaces(tool: str) -> str:
    """List capture interfaces only; this command performs no capture or scan."""
    try:
        result = subprocess.run([tool, "-D"], shell=False, capture_output=True,
                                text=True, timeout=10, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SensorError("cannot list interfaces; check capture driver/permissions") from exc
    if result.returncode:
        raise SensorError("capture interface listing failed; check driver/permissions")
    return result.stdout[:65536]


def capture_argv(tool: str, interface: str, duration: int, max_bytes: int, out: Path) -> list[str]:
    """Construct explicit duration/file autostops with room for native block overhead."""
    if (not interface or not interface.strip() or any(c in interface for c in "\0\r\n:")
            or interface.startswith("-") or interface.lower().startswith(("tcp@", "rpcap", "\\\\.\\pipe\\"))):
        raise SensorError("an explicit interface is required")
    if not isinstance(duration, int) or not 1 <= duration <= 3600:
        raise SensorError("duration must be 1–3600 seconds")
    if not isinstance(max_bytes, int) or not MIB <= max_bytes <= MAX_INPUT_BYTES:
        raise SensorError("capture byte budget must be 1–100 MiB")
    kib = (max_bytes - 128 * 1024) // 1024
    return [tool, "-q", "-p", "-i", interface, "-s", "65535", "-F", "pcap", "-a", f"duration:{duration}",
            "-a", f"filesize:{kib}", "-w", str(out)]


def capture(tool: str, interface: str, duration: int, max_bytes: int, folder: Path) -> Path:
    out = folder / "capture.pcap"
    if out.exists():
        raise SensorError("capture output already exists")
    run_command(capture_argv(tool, interface, duration, max_bytes, out),
                duration + 20, folder / "capture.log")
    if not out.is_file() or not 0 < out.stat().st_size <= max_bytes:
        raise SensorError("capture is missing, empty or exceeds its byte budget; not submitted")
    return out


def convert(pcap: Path, argv_template: Sequence[str], folder: Path, timeout: int = 300) -> Path:
    """Invoke one trusted converter and require exactly one bounded CSV result."""
    if not pcap.is_file() or not 0 < pcap.stat().st_size <= MAX_INPUT_BYTES:
        raise SensorError("converter input must be a nonempty capture of at most 100 MiB")
    template = parse_converter(json.dumps(list(argv_template)))
    executable = discover_tool(template[0])
    if not executable:
        raise SensorError("converter executable unavailable")
    out = folder / "converted"
    out.mkdir(exist_ok=False)
    argv = [a.replace("{pcap}", str(pcap.resolve())).replace("{output}", str(out.resolve()))
            for a in template]
    argv[0] = executable
    run_command(argv, timeout, folder / "converter.log")
    csvs = sorted(out.glob("*.csv"))
    if len(csvs) != 1 or not 0 < csvs[0].stat().st_size <= MAX_INPUT_BYTES:
        raise SensorError("converter must emit exactly one nonempty CSV of at most 100 MiB")
    return csvs[0]


def validate_csv(source: Path, target: Path, features: Sequence[str]) -> int:
    """Reject missing/invalid values and strip labels/arbitrary columns before scoring."""
    if source.resolve() == target.resolve():
        raise SensorError("validated output must differ from input")
    if target.exists():
        raise SensorError("validated output already exists")
    if not source.is_file() or not 0 < source.stat().st_size <= MAX_INPUT_BYTES:
        raise SensorError("input CSV must be nonempty and at most 100 MiB")
    count = 0
    created = False
    try:
        with source.open(encoding="utf-8-sig", newline="") as inp, target.open("x", encoding="utf-8", newline="") as out:
            created = True
            reader = csv.reader(inp, strict=True)
            header = [c.strip() for c in next(reader)]
            if len(set(header)) != len(header) or any(not c for c in header):
                raise SensorError("duplicate or empty CSV headers")
            missing = [f for f in features if f not in header]
            if missing:
                raise SensorError(f"{len(missing)} model features missing: {', '.join(missing[:5])}")
            keep = list(features) + [c for c in META_COLUMNS if c in header and c not in features]
            indices = [header.index(c) for c in keep]
            fi = [header.index(c) for c in features]
            writer = csv.writer(out)
            writer.writerow(keep)
            for row in reader:
                if len(row) != len(header):
                    raise SensorError(f"malformed CSV row {count + 2}")
                try:
                    valid = all(math.isfinite(float(row[i])) for i in fi)
                except (ValueError, OverflowError):
                    valid = False
                if not valid:
                    raise SensorError(f"nonnumeric or nonfinite features at CSV row {count + 2}")
                count += 1
                if count > MAX_ROWS:
                    raise SensorError("CSV exceeds 200000 rows")
                writer.writerow([row[i] for i in indices])
    except (OSError, UnicodeError, csv.Error, StopIteration) as exc:
        if created:
            target.unlink(missing_ok=True)
        raise SensorError("cannot parse/write UTF-8 feature CSV") from exc
    except SensorError:
        if created:
            target.unlink(missing_ok=True)
        raise
    if count == 0:
        target.unlink(missing_ok=True)
        raise SensorError("CSV has no flow rows")
    return count


def csv_batches(source: Path) -> Iterator[tuple[int, bytes]]:
    """Bound every API CSV by both rows and bytes, preserving complete rows."""
    with source.open(encoding="utf-8", newline="") as stream:
        reader = csv.reader(stream)
        header = next(reader)
        def encode(row: list[str]) -> bytes:
            buf = io.StringIO(newline="")
            csv.writer(buf).writerow(row)
            return buf.getvalue().encode("utf-8")
        head = encode(header)
        body = bytearray(head)
        rows = 0
        for row in reader:
            data = encode(row)
            if len(head) + len(data) > MAX_BATCH_BYTES:
                raise SensorError("one CSV row exceeds the API batch byte limit")
            if rows and (rows == MAX_BATCH_ROWS or len(body) + len(data) > MAX_BATCH_BYTES):
                yield rows, bytes(body)
                body, rows = bytearray(head), 0
            body.extend(data)
            rows += 1
        if rows:
            yield rows, bytes(body)


def loopback_url(url: str) -> str:
    """Literal loopback only: no name resolution, credentials, proxies or redirects."""
    try:
        parsed = urllib.parse.urlsplit(url)
        address = ipaddress.ip_address(parsed.hostname or "")
        port = parsed.port
    except ValueError as exc:
        raise SensorError("API URL requires a literal loopback IP") from exc
    if (parsed.scheme not in ("http", "https") or not address.is_loopback or
            parsed.username or parsed.password or parsed.query or parsed.fragment or
            parsed.path != "/sensor/ingest" or port == 0):
        raise SensorError("only a loopback /sensor/ingest API URL is permitted")
    return url


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str,
                         headers: Any, newurl: str) -> None:
        return None


def push_batch(url: str, key: str, payload: bytes, session: str, batch: str,
               sensor_id: str | None = None) -> dict[str, Any]:
    """Send a bounded multipart file only to the local scoring process."""
    loopback_url(url)
    if not key or any(c in key for c in "\r\n"):
        raise SensorError("a nonempty API key environment variable is required for ingestion")
    fields = {"sensor_session": session, "batch_id": batch}
    if sensor_id is not None:
        fields["sensor_id"] = sensor_id
    if any(not TOKEN.fullmatch(value) for value in fields.values()):
        raise SensorError("session/batch/sensor identifiers require 1–64 safe token characters")
    if not payload or len(payload) > MAX_BATCH_BYTES:
        raise SensorError("invalid API CSV byte size")
    boundary = "sensor_" + uuid.uuid4().hex
    chunks: list[bytes] = []
    for name, value in fields.items():
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'.encode())
    chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="file"; filename="flows.csv"\r\nContent-Type: text/csv\r\n\r\n'.encode())
    chunks.extend([payload, f"\r\n--{boundary}--\r\n".encode()])
    request = urllib.request.Request(url, data=b"".join(chunks), method="POST",
                                     headers={"X-API-Key": key,
                                              "Content-Type": f"multipart/form-data; boundary={boundary}"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            data = response.read(MIB + 1)
        if len(data) > MIB:
            raise SensorError("API response exceeds 1 MiB")
        body = json.loads(data)
        if not isinstance(body, dict):
            raise SensorError("API response must be a JSON object")
        return body
    except (OSError, ValueError, urllib.error.URLError) as exc:
        raise SensorError("local API ingestion failed; check server status and configured key") from exc
