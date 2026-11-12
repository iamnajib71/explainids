# Passive local sensor contract

The sensor explicitly lists interfaces, records a bounded passive capture on a user-selected interface, invokes a trusted local flow converter, validates its CSV against a saved model feature schema, and optionally submits batches to the loopback API. It never scans, chooses an interface automatically, generates traffic, installs drivers or changes privileges/network settings.

## Commands and inputs

- `doctor`: discover `dumpcap` or `tshark` through PATH or an explicit executable, optionally inspect a converter argument array and model card. No capture.
- `interfaces`: execute only the selected capture tool's `-D` with a timeout. No capture.
- `capture`: requires `--interface`, `--duration`, `--max-bytes`, `--converter-argv` (JSON string array), and a model card. Outputs go into a fresh session below the repository's ignored `data/sensor/`. No existing session is overwritten.
- `ingest`: validate an existing local CSV against the model card, write a sanitised local copy/session manifest, optionally send to the loopback API. No capture.

The converter argument array must contain `{pcap}` and `{output}` placeholders. The first element resolves to an executable; later elements substitute the actual capture file and fresh output directory. Run with `shell=False`, a timeout, and captured logs in the session. This configuration executes trusted local code and is not accepted from a network request. Exactly one nonempty CSV must be emitted in the output directory. Converter binaries/build hashes and model-card hashes are retained; a schema match does not prove compatible feature semantics. The pinned corrected extractor lineage described in `docs/LOCAL_SENSOR.md` is required for meaningful model scoring.

## Capture bounds

Duration is 1–3600 seconds; file budget is 1 MiB–100 MiB. Command uses explicit interface, duration and file-size autostops, snapshot length 65535, a fresh output path and a wall timeout. Reserve 128 KiB below the requested cap for packet/block overhead and verify actual size afterward. Reject oversized, empty or missing output; never submit it. Tool/native buffering means the postcondition is verified rather than a byte-precise operating-system quota. Keep raw output on failure for audit. Capture-tool permissions/driver setup are the operator's prerequisite.

## CSV and ingestion

Read `features` as a nonempty unique string array from the supplied model card. Require every feature header exactly once after whitespace stripping; reject duplicate headers, missing fields, empty CSVs, malformed rows, nonnumeric/nonfinite feature values and over-limit inputs. Never fill absent features or invalid values. Preserve only model features and optional `Src IP`, `Dst IP`, `Timestamp` in a sanitised CSV; omit labels/truth and arbitrary other columns. Return row count and file hash, with no accuracy claim.

Optional ingestion sends multipart `file`, `sensor_session`, `batch_id` and optional `sensor_id` to `/sensor/ingest` with `X-API-Key`. Require a nonempty key from an environment variable; do not put it on the command line. Each file is at most 5 MiB and 1000 rows. Session/batch tokens are deterministic within the saved session; retries reuse the manifest session ID and batch IDs. Only literal loopback IP destinations are permitted, proxies/redirects are disabled, and response size/time are bounded. No external upload mode is implemented. The API independently validates inputs and pseudonymises source identifiers; local originals still require careful retention.

## Evidence and failure behaviour

Every session records UTC time, input/model-card and launcher executable hashes, command settings without API credentials, status/errors, row counts, output hashes and upload acknowledgements where available. Local converter build lineage must accompany a configured wrapper; a launcher executable hash alone does not verify its nested script/JVM/native-library build. External-tool logs may contain captured host identifiers and remain private in ignored storage. An unavailable driver/tool/converter, failed command or schema mismatch produces nonzero exit and an explanatory local error; there is no synthetic-data fallback. Partial successful API batches are recorded before a later failure. No capture test is run against a real interface in automated tests.

## Verification

Tests must verify explicit-interface/bounds argument construction, local output confinement, placeholder validation, timeout/error propagation, strict schema/finite checks, zero-truth upload, row/byte batch limits, loopback/redirect constraints and a mocked end-to-end converter flow. Real capture, packet-loss accounting and converter feature semantics remain integration gates requiring the operator's actual owned-network run.
