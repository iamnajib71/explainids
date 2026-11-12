#!/usr/bin/env bash
# Deploy ExplainIDS to Azure Container Apps (Consumption plan, scale to zero) with HTTPS, sign-in and a budget.
# Run in Azure Cloud Shell (bash) or anywhere with `az` signed in. Idempotent: rerun to update the image or settings.
#
#   IMAGE=ghcr.io/<owner>/explainids:<tag> \
#   EXPLAINIDS_USERS='analyst:pbkdf2_sha256$...' \
#   bash infra/azure/deploy.sh
#
# Optional: RG (explainids-rg), LOCATION (australiaeast), APP (explainids), ENV_NAME (explainids-env),
# BUDGET (10, USD per month), BUDGET_EMAIL (default: alert the subscription Owners), EXPLAINIDS_API_KEY (for a remote collector), EXPLAINIDS_SESSION_SECRET.
# Cost: one replica of 0.5 vCPU / 1 GiB only while requests arrive, inside the monthly free grant
# (180,000 vCPU-s, 360,000 GiB-s, 2 million requests); no registry, no log workspace. Remove everything with
# infra/azure/shutdown.sh.
set -euo pipefail

RG=${RG:-explainids-rg}
LOCATION=${LOCATION:-australiaeast}
APP=${APP:-explainids}
ENV_NAME=${ENV_NAME:-explainids-env}
BUDGET=${BUDGET:-10}
: "${IMAGE:?set IMAGE to a public image, e.g. ghcr.io/<owner>/explainids:<tag> (see infra/azure/README.md)}"
: "${EXPLAINIDS_USERS:?set EXPLAINIDS_USERS from python scripts/hash_password.py <name>; a public console needs sign-in}"
SESSION_SECRET=${EXPLAINIDS_SESSION_SECRET:-$(openssl rand -hex 32)}
API_KEY=${EXPLAINIDS_API_KEY:-$(openssl rand -hex 24)}

az extension add --name containerapp --upgrade --only-show-errors
az provider register --namespace Microsoft.App --wait --only-show-errors
az group create -n "$RG" -l "$LOCATION" --tags project=explainids -o none

if ! az containerapp env show -n "$ENV_NAME" -g "$RG" -o none 2>/dev/null; then
  # No Log Analytics workspace: it is the one piece that would bill by ingestion.
  az containerapp env create -n "$ENV_NAME" -g "$RG" -l "$LOCATION" --logs-destination none -o none
fi

SECRETS=(users="$EXPLAINIDS_USERS" session="$SESSION_SECRET" apikey="$API_KEY")
ENVVARS=(EXPLAINIDS_USERS=secretref:users EXPLAINIDS_SESSION_SECRET=secretref:session
         EXPLAINIDS_API_KEY=secretref:apikey EXPLAINIDS_REQUIRE_HTTPS=1)

if az containerapp show -n "$APP" -g "$RG" -o none 2>/dev/null; then
  az containerapp secret set -n "$APP" -g "$RG" --secrets "${SECRETS[@]}" -o none
  az containerapp update -n "$APP" -g "$RG" --image "$IMAGE" --set-env-vars "${ENVVARS[@]}" -o none
else
  az containerapp create -n "$APP" -g "$RG" --environment "$ENV_NAME" --image "$IMAGE" \
    --ingress external --target-port 8000 --transport auto \
    --cpu 0.5 --memory 1.0Gi --min-replicas 0 --max-replicas 1 \
    --secrets "${SECRETS[@]}" --env-vars "${ENVVARS[@]}" -o none
fi
# HTTPS only at the edge as well as in the app.
az containerapp ingress update -n "$APP" -g "$RG" --allow-insecure false -o none

# Alerts go to BUDGET_EMAIL if set, otherwise to the subscription's Owners (no address needed in this script).
if [ -n "${BUDGET_EMAIL:-}" ]; then TO="\"contact-emails\": [\"$BUDGET_EMAIL\"]"; else TO='"contact-roles": ["Owner"]'; fi
start=$(date -u +%Y-%m-01)
cat > /tmp/explainids-budget.json <<JSON
{"actual50": {"enabled": true, "operator": "GreaterThanOrEqualTo", "threshold": 50, $TO},
 "actual100": {"enabled": true, "operator": "GreaterThanOrEqualTo", "threshold": 100, $TO}}
JSON
az consumption budget create-with-rg -g "$RG" -n explainids-budget --amount "$BUDGET" --category Cost     --time-grain Monthly --time-period "{\"start-date\":\"${start}T00:00:00Z\",\"end-date\":\"2027-12-31T00:00:00Z\"}"     --notifications @/tmp/explainids-budget.json -o none   || echo "Budget not created from the CLI; set one in the portal: Cost Management > Budgets (US\$$BUDGET, alerts at 50%/100%)."
rm -f /tmp/explainids-budget.json

FQDN=$(az containerapp show -n "$APP" -g "$RG" --query properties.configuration.ingress.fqdn -o tsv)
echo "Console: https://$FQDN   (first request after idle takes ~30 s while a replica starts)"
if [ -z "${EXPLAINIDS_API_KEY:-}" ]; then
  echo "A collector API key was generated and stored as a container secret; read it with:"
  echo "  az containerapp secret show -n $APP -g $RG --secret-name apikey --query value -o tsv"
fi
