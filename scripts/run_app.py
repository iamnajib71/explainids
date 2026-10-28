"""Start the source-checkout web app on loopback without starting packet capture."""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import threading
import time
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPENDENCIES = ("fastapi", "uvicorn", "numpy", "pandas", "sklearn", "lightgbm", "xgboost",
                "shap", "joblib", "pyarrow", "multipart")


def model_directory(explicit: str | None, root: Path = ROOT) -> Path:
    configured = explicit or os.environ.get("EXPLAINIDS_MODEL_DIR")
    return Path(configured).expanduser().resolve() if configured else root / "models"


def readiness(model_dir: Path, root: Path = ROOT) -> dict:
    missing_dependencies = [name for name in DEPENDENCIES if importlib.util.find_spec(name) is None]
    missing_files = [name for name in ("api/main.py", "web/index.html", "web/app.js")
                     if not (root / name).is_file()]
    supported_python = sys.version_info >= (3, 11)
    trained = (model_dir / "detector.joblib").is_file()
    return {"ready": supported_python and not missing_dependencies and not missing_files,
            "python": sys.version.split()[0], "supported_python": supported_python,
            "checkout": str(root), "bind": "127.0.0.1", "missing_dependencies": missing_dependencies,
            "missing_files": missing_files, "model_directory": str(model_dir),
            "trained_detector_present": trained,
            "mode": "trained artifacts present; compatibility checked on load" if trained else "synthetic demonstration",
            "capture_started": False,
            "sensor_note": "Live monitoring needs the separately configured host sensor and compatible flow extractor."}


def port_number(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def open_when_ready(server, url: str, stop: threading.Event) -> None:
    deadline = time.monotonic() + 30
    while not stop.wait(0.1) and time.monotonic() < deadline:
        if server.started:
            webbrowser.open(url)
            return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="print readiness JSON; do not start anything")
    parser.add_argument("--port", type=port_number, default=8000)
    parser.add_argument("--model-dir", help="trusted local model-artifact folder")
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    model_dir = model_directory(args.model_dir)
    status = readiness(model_dir)
    if args.check:
        print(json.dumps(status, indent=2))
        return 0 if status["ready"] else 1
    if not status["ready"]:
        print(json.dumps(status, indent=2), file=sys.stderr)
        print('Install from the checkout with: python -m pip install -e ".[api]"', file=sys.stderr)
        return 1
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "src"))
    os.environ["EXPLAINIDS_MODEL_DIR"] = str(model_dir)
    import uvicorn

    url = f"http://127.0.0.1:{args.port}"
    print(f"ExplainIDS: {url}", flush=True)
    print("Local interface only. Packet capture is not started by this command.", flush=True)
    server = uvicorn.Server(uvicorn.Config("api.main:app", host="127.0.0.1", port=args.port, log_level="info"))
    stop = threading.Event()
    opener = None
    if not args.no_browser:
        opener = threading.Thread(target=open_when_ready, args=(server, url, stop), daemon=True)
        opener.start()
    try:
        server.run()
    finally:
        stop.set()
        if opener:
            opener.join(timeout=1)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
