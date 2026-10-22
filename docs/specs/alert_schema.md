# Alert format (API ↔ dashboard contract)

Produced by `ids.alerts.build_alerts` and returned by `POST /predict` and `GET /alerts`. The dashboard depends only on this format, so UI work can proceed on the synthetic demo model before real models exist.

| Field | Type | Notes |
|---|---|---|
| `alert_id` | string (UUID) | |
| `time` | string (ISO 8601) | Flow timestamp |
| `source` | string | Pseudonymised host (`host-xxxxxxxxxx`) once data leaves the lab |
| `predicted_class` | string | Canonical class (`ids.data.canonical_label`), or `BENIGN` for pure outliers |
| `confidence` | float \| null | Max class probability |
| `outlier` | bool | Isolation Forest flagged the flow (benign-trained, validation-tuned threshold) |
| `anomaly_score` | float \| null | Lower = more anomalous |
| `attack` | object | `technique_id`, `technique`, `tactic`, `severity`, `guidance`, `url`: a **candidate** for analyst confirmation; `technique` is `unmapped` when no candidate fits |
| `severity` | string | `Info` · `Medium` · `High` · `Critical` |
| `summary` | string | Plain-language sentence for non-specialists, ≤ 30 words (US1) |
| `explanation` | list | Top SHAP features: `{feature, value, contribution}` |
| `status` | string | `open` · `confirmed` · `dismissed` (US5) |

Incidents (`GET /incidents`) group alerts by `source`, candidate technique and a time window (FR6).
