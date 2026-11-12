#!/usr/bin/env bash
# Stop paying for ExplainIDS on Azure.
#   bash infra/azure/shutdown.sh          pause: scale to zero and remove public ingress (keeps settings)
#   bash infra/azure/shutdown.sh --delete delete the whole resource group (app, environment, budget)
set -euo pipefail
RG=${RG:-explainids-rg}
APP=${APP:-explainids}

if [ "${1:-}" = "--delete" ]; then
  az group delete -n "$RG" --yes --no-wait
  echo "Deleting resource group $RG; check with: az group exists -n $RG"
else
  az containerapp update -n "$APP" -g "$RG" --min-replicas 0 --max-replicas 1 -o none
  az containerapp ingress disable -n "$APP" -g "$RG" -o none
  echo "Paused: no public endpoint, no replicas. Resume with: az containerapp ingress enable -n $APP -g $RG --type external --target-port 8000"
fi
