# Local application entry point

The source checkout must start from any working directory on a supported Python installation. `scripts/run_app.py` is the application entry point. It binds only to `127.0.0.1`, never starts packet capture, and serves the existing API and browser console.

## Contract

- Python 3.11 or later and the declared API/model dependencies are required.
- `--check` emits dependency, layout and model-artifact readiness as JSON without starting a server, fitting a model, opening a browser or capturing packets. Missing prerequisites produce a nonzero exit status.
- `--port` accepts an integer from 1 to 65535; the default is 8000. Remote bind addresses are not accepted by this entry point.
- `--model-dir` overrides the configured model folder; otherwise preserve `EXPLAINIDS_MODEL_DIR`, then default to the checkout's `models/` directory. Resolve relative explicit paths against the invoking directory.
- No trained detector means replay/demo mode, which must remain visibly distinguished from real sensor input. Artifact presence is not a model compatibility or quality guarantee.
- Normal startup validates the checkout and dependencies, starts the existing ASGI app, and opens the local browser after the server starts unless `--no-browser` is supplied.
- The web/API process runs with ordinary user privileges. Packet-capture privileges belong to the separate explicit host sensor, not to this launcher.
- Shutdown follows the server's normal interrupt handling. No background service, startup registration, cloud deployment or network-device scan is created.

Tests must cover missing prerequisites/layout, model-folder precedence, invalid ports and the fixed loopback binding/startup boundary. This entry point supports a source checkout; a self-contained signed desktop installer is a separate packaging deliverable.
