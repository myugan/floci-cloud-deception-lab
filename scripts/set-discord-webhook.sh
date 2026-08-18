#!/bin/sh
# Applies the Discord webhook URL directly as the discord-webhook Secret
# in the management cluster — never written to a tracked file, so
# there's nothing to accidentally commit.
#
# Get a webhook URL from Discord: Server Settings -> Integrations ->
# Webhooks -> New Webhook -> Copy Webhook URL.
#
# Usage: ./set-discord-webhook.sh <webhook-url>

set -eu

: "${1:?usage: ./set-discord-webhook.sh <webhook-url>}"

kubectl create namespace floci-deception-alerts --dry-run=client -o yaml | kubectl apply -f -

kubectl create secret generic discord-webhook \
  --namespace=floci-deception-alerts \
  --from-literal=url="$1" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "applied — restart the tailer to pick it up:" >&2
echo "  kubectl -n floci-deception-alerts delete pod -l app=discord-alert-tailer" >&2
