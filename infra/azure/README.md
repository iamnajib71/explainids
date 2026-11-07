# Azure deployment (Azure for Students, $0)

The console and API run as one container on **Azure Container Apps**, Consumption plan. HTTPS comes from the
platform's managed certificate on `*.azurecontainerapps.io`, and the app itself also refuses plain HTTP
(`EXPLAINIDS_REQUIRE_HTTPS=1`). With sign-in configured, every route that scores traffic, writes data or returns
alerts needs a signed-in session or the collector API key.

| Choice | Why it costs nothing |
|---|---|
| Consumption plan, 0.5 vCPU / 1 GiB, `min-replicas 0`, `max-replicas 1` | No charge while scaled to zero; the monthly free grant (180,000 vCPU-s, 360,000 GiB-s, 2 million requests per subscription) covers about 100 active hours |
| Public image on GitHub Container Registry | No Azure Container Registry (its cheapest tier bills daily) |
| `--logs-destination none` | No Log Analytics workspace, which bills by data ingested |
| Budget alert, US$10 per month, emails at 50% and 100% | Warns before the student credit is touched |
| `shutdown.sh` | One command to pause or delete everything |

Source for the free grant and scale-to-zero billing:
[Billing in Azure Container Apps](https://learn.microsoft.com/en-us/azure/container-apps/billing).

## 1. Make the console accounts

One per team member, on your own machine (the password is never written to disk):

```bash
python scripts/hash_password.py analyst
```

Join several `name:hash` lines with commas. These hashes are secrets: keep them out of git and chat.

## 2. Publish the image

Build where the trained artefacts exist (`models/detector.joblib`, `model_card.json`, `replay.parquet`), so the
image serves the real detector rather than the synthetic demo:

```bash
docker build -t ghcr.io/<owner>/explainids:v0.3.0 .
docker run --rm --entrypoint ls ghcr.io/<owner>/explainids:v0.3.0 /app /app/models   # nothing private inside
docker push ghcr.io/<owner>/explainids:v0.3.0
```

Pushing needs `docker login ghcr.io` with a GitHub token that has `write:packages`. Then make the package public
in GitHub (Packages > explainids > Package settings > Change visibility). The `.dockerignore` allowlist admits
only `src/`, `api/`, `web/` and the three model artefacts; coursework, data and environments never enter the image.

## 3. Deploy

In [Azure Cloud Shell](https://shell.azure.com) (bash; nothing to install), after cloning the repository:

```bash
IMAGE=ghcr.io/<owner>/explainids:v0.3.0 EXPLAINIDS_USERS='<name:hash,...>' bash infra/azure/deploy.sh
```

It creates resource group `explainids-rg`, the environment, the app with secrets, HTTPS-only ingress and the
budget (alerts go to the subscription's Owners, or to `BUDGET_EMAIL` if set), then prints the console URL. Rerun it with a new `IMAGE` to update. The first request after an idle
period takes about 30 seconds while a replica starts.

A collector on your own network sends batches to `https://<app>/sensor/ingest` with the API key printed by the
script (`X-API-Key` header). Capture still only runs on hosts you own and may monitor.

## 4. Stop paying

```bash
bash infra/azure/shutdown.sh            # pause: no public endpoint, no replicas, settings kept
bash infra/azure/shutdown.sh --delete   # delete the resource group and everything in it
```

## Limits of this deployment

- Triage decisions are stored in SQLite inside the container and are lost when it scales to zero or is
  redeployed. Export the repair set (`/triage/repair-set.csv`) after a session; durable storage would need an
  Azure Files mount, which is not free.
- One replica only: the sign-in rate limit and the sensor feed are in memory.
- Sessions last 8 hours; changing `EXPLAINIDS_SESSION_SECRET` signs everyone out.
