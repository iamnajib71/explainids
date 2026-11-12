# Passive local sensor

The sensor records a short, bounded capture on an explicitly selected interface, runs your trusted local flow converter, validates the output against your saved model card and optionally submits it to the local application. It generates no traffic and installs no capture driver or converter. The browser's local-sensor view receives observations through `/sensor/ingest`; benchmark replay remains separate.

## Prerequisites and current limits

- Python 3.11 or later and the project's environment. `python scripts/run_sensor.py --help` works from a source checkout.
- Installed `dumpcap` or `tshark`, found through PATH or `--capture-tool`. On Windows the capture driver and its permissions must already be configured; the sensor does not request elevation or install Npcap.
- A saved model and its matching `models/model_card.json`. The current trained model expects 83 flow features. The sensor validates the actual feature list in the card, rather than assuming any generic flow schema is compatible.
- A compatible corrected flow converter. The existing research lineage pins commit `91140973f64c3b4e94f5e5ce578284086570226b`; its connection-time semantics matter. The existing Linux/JVM/native-library build is **not** a native Windows executable. A driver alone does not make conversion portable. Use a known working local Linux installation or an explicitly configured wrapper that handles Windows-to-Linux paths; do not claim a container/Windows adapter has been supplied or tested here.

The capture CLI is implemented and tested with fixtures/mocks. Real interface capture and the external converter's cross-platform runtime are separate integration prerequisites. Schema validation cannot establish that feature units, timeouts or definitions match the training extractor. No synthetic feature or missing-column fallback exists.

## Inspect dependencies and interfaces

These commands do not capture traffic:

```powershell
python scripts/run_sensor.py doctor
python scripts/run_sensor.py interfaces --capture-tool 'C:\Program Files\Wireshark\dumpcap.exe'
```

`doctor` returns status 2 until the capture executable, model card and explicitly configured converter executable are available. It reports that driver permissions and converter semantics remain unverified. Supply a trusted converter argument array to inspect it as well:

```powershell
python scripts/run_sensor.py doctor --converter-argv '["bash","/absolute/path/to/pinned/cfm","{pcap}","{output}"]'
```

The array is a configuration example for a compatible Linux environment, not a claim that that path exists. Every array element is one literal process argument. `{pcap}` becomes the captured file path; `{output}` becomes a fresh converter-output directory. Unknown placeholders are rejected. The converter must emit exactly one nonempty `.csv` in that directory. Trusted local wrappers may adapt a converter's invocation or path conventions; they must preserve feature semantics and terminate their child processes when cancelled. No shell command string is evaluated by the sensor. Do not put credentials in converter arguments: command metadata and tool output are retained locally.

## Capture a bounded session

Only choose an interface on a network you own or are authorised to observe. Use an interface identifier from the listing. For a compatible Linux capture/converter installation:

```bash
python scripts/run_sensor.py capture --interface eth0 --duration 30 --max-bytes 10485760 --converter-argv '["bash","/absolute/path/to/pinned/cfm","{pcap}","{output}"]'
```

The CLI requires the interface, duration, byte budget and converter arguments; it never chooses an interface. Remote-capture URLs/pipes are rejected. It uses non-promiscuous mode, standard pcap output, a 65535-byte snapshot limit, duration/file autostops and a wall timeout. An interface generally exposes only traffic available to that host; this does not promise visibility across the whole LAN. Existing driver/interface state can still affect visibility.

The duration is 1–3600 seconds and the capture budget 1–100 MiB. Native file-size stops are approximate, so the command leaves overhead headroom and checks actual file size before conversion/submission. Missing, empty or oversized captures fail. A raw capture may include payloads, credentials or private addresses; the CLI says this before capture and retains it only in the ignored local session. Stop capture and review retention before sharing any packet or converter log.

Output is under `data/sensor/<new-session-id>/`: `capture.pcap`, capture/converter logs, converted CSV, sanitised `validated.csv` and an atomic `manifest.json`. The manifest retains source/model/tool hashes, bounded settings, row count, status and upload acknowledgements. Failed sessions preserve relevant raw evidence and an error. Files are not automatically deleted or committed.

## Validate existing flow CSV without capture

```powershell
python scripts/run_sensor.py ingest 'data/lab/your-session/flows.csv' --model-card models/model_card.json
```

Validation requires every model feature and finite numeric values in every row. It rejects missing/duplicate columns, malformed/empty CSVs and invalid values instead of filling or silently skipping rows. Output contains model features and optional source/destination/time metadata; labels, truth and arbitrary additional columns are removed. The complete CSV is validated before any network submission. This is compatible flow ingestion, not evidence that a file was newly captured.

## Submit to the local application

Start the local application with its real saved model and a configured API key, using the local app instructions. Set the sensor's matching key in the environment using your local secret-management method. The default environment-variable name is `EXPLAINIDS_API_KEY`; never pass the key as a command-line argument or paste it into screenshots.

```powershell
python scripts/run_sensor.py ingest 'data/lab/your-session/flows.csv' --push
```

Or add `--push` to the bounded `capture` command. Requests go to `http://127.0.0.1:8000/sensor/ingest` by default. `--api-url` can choose another port or literal loopback address at the same endpoint, including bracketed IPv6 loopback. External addresses and hostname resolution, proxies and redirects are blocked. There is no remote/cloud upload mode. Loopback requests still contain source metadata; the API independently validates and pseudonymises it before displaying the local-sensor feed. Local original files remain sensitive.

Each multipart CSV is bounded to 1000 rows and 5 MiB, with `sensor_session`, `batch_id` and optional `sensor_id`. API authentication uses `X-API-Key`. The CLI requires a key even if a development API has authentication disabled. It makes no packet/drop-count claim when the capture tool's logs have not been parsed. Live observations do not have verified truth labels, so no accuracy/precision/recall metric is inferred from them.

The manifest records a session token. To retry the **same validated file** after a partial failure, reuse that token with `--sensor-session TOKEN` and `--push`; deterministic batch IDs let the API recognise previously accepted identical data. Do not reuse a token for changed/reordered data. Deduplication/history are bounded in server memory and reset on restart, so this is not an exactly-once persistent delivery guarantee.

## Failure checks and verification

Run `doctor` first. A missing tool/driver, rejected permission, converter timeout, incompatible feature schema, invalid CSV or API error ends with status 2. No capture starts when command prerequisites/bounds or requested destination are invalid. The CLI does not change privileges, scan the LAN, install packages or replace your model.

Automated tests cover command bounds, local-only interfaces/destinations, strict validation, converter execution with a harmless fixture, batch limits and multipart metadata without real capture. Real owned-network verification still needs a short operator-selected session, interface/driver evidence, matching extractor semantics, packet/drop logs, API acknowledgement and a visible local-sensor result. A successfully displayed alert is a model output, not proof of compromise or proven operational effectiveness.

Capture flags follow the official [dumpcap manual](https://www.wireshark.org/docs/man-pages/dumpcap.html). The project interface contract is in [local_sensor.md](specs/local_sensor.md).

## Windows capture and conversion path

Two prerequisites sit between a Windows host and a scored flow. `doctor` reports each one.

**Conversion — working.** The corrected extractor is built inside WSL (`data/lab/tools/EXTRACTOR_SETUP.md`)
and only understands WSL paths, while the sensor substitutes resolved Windows paths into the converter
argv. `scripts/wsl_convert.py` bridges the two: it translates `H:\dir\file` to `/mnt/h/dir/file`, invokes
the extractor through `wsl.exe` with `shell=False`, a timeout and captured logs, and requires exactly one
nonempty CSV. Use it as the trusted converter:

```
--converter-argv "[\"<python>\", \"scripts/wsl_convert.py\", \"{pcap}\", \"{output}\"]"
```

Verified on 29 October 2026 against a recorded lab capture (`data/lab/run_20261025T051149Z/traffic.pcap`):
**305 rows emitted, matching the 305 rows recorded for that run, with all 83 model-card features present
and none missing after alignment.** That establishes schema compatibility and reproduction of the earlier
extraction; it is not evidence about live capture conditions.

**Capture — not yet available on this host.** `doctor` finds no `dumpcap` or `tshark`. Discovery checks
PATH and the standard Wireshark install directories, so installing Wireshark (which bundles Npcap) is
sufficient; no PATH edit is needed. That install requires administrator rights and a driver, so it is an
operator action and is deliberately not automated here. WSL2 runs in its own network namespace and cannot
observe host traffic, so capturing the host network needs the Windows-side tool.

After installing, confirm with `doctor`, list adapters with `interfaces`, and capture only from an
interface you are authorised to observe, with an explicit duration and byte bound. Passive capture sees
only traffic present at that observation point.
