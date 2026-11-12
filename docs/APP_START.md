# Start the local application

ExplainIDS runs as a local web application from this source checkout. It supports replay and CSV analysis; live observations arrive through a separate explicitly started passive sensor. Starting the app does not capture or scan the network.

## Install and check

Use Python 3.11 or later in a virtual environment. From the checkout:

```text
python -m pip install -e ".[api]"
python scripts/run_app.py --check
python scripts/run_app.py
```

The launcher opens `http://127.0.0.1:8000` after startup. Use `--no-browser` to keep it terminal-only or `--port 8765` for another local port. Interrupt the terminal process to stop the app. You can invoke the launcher by its full path from another working directory.

Use only trusted model artifacts. Set `EXPLAINIDS_MODEL_DIR` or pass `--model-dir` to select their folder. Without a trained detector, the app uses a synthetic demonstration; this is not a live-network protection result. The readiness check reports file presence and dependencies, not model quality.

## Local network workflow

1. Start this app with loopback binding.
2. Configure the separate host sensor and the compatible flow extractor; read [local sensor setup](LOCAL_SENSOR.md).
3. Explicitly select an authorised local interface and bounded capture period. Review the capture/storage settings first.
4. Send extracted flows to the local sensor ingestion endpoint and select **Local sensor** in the console. Replay is a different mode and must not be mistaken for observed traffic.

An ordinary interface normally sees that host's traffic and relevant broadcast/multicast traffic, not every connection between other devices on a switched network. Whole-segment visibility needs an authorised router capture, mirror port or equivalent observation point. The app does not reconfigure your router, intercept other devices, guess passwords or generate attack traffic.

The current model is a research detector. Legitimate-service false alerts and transfer limitations are documented; review candidate alerts rather than treating them as proof of compromise. The passive sensor does not make the trained model universally valid on a new network.

## Portability boundary

The Python/API/console checkout is portable where its dependencies are supported. Capture additionally requires a supported host capture tool/driver and privileges; the original flow extractor has native dependencies. Windows, Linux and macOS must pass their own dependency and end-to-end checks before that platform is marked verified. Docker packaging does not automatically provide host-interface visibility on every operating system.

References: [capture interface and bounded-file options](https://www.wireshark.org/docs/man-pages/dumpcap.html), [switched Ethernet visibility](https://wiki.wireshark.org/CaptureSetup/Ethernet), [platform capture privileges](https://wiki.wireshark.org/CaptureSetup/CapturePrivileges).
