#!/bin/sh
# Thin Kubernetes wrapper around shared/generate-canary-creds.sh --
# applies the generated key as the canary-aws-creds Secret in the
# floci-deception namespace, and writes canary-access-key-id.yaml
# alongside this script: just the access key ID (not the secret),
# for discord-alert-tailer's canary-key filter. That Secret can't be
# applied here -- floci-deception-alerts lives on the *management*
# cluster (a different kubectl context entirely, see README), not
# just a different namespace on this one. Least-privilege on purpose:
# alerting only needs the ID to recognize "our canary" vs. some other
# credential, never the secret itself.
#
# Run this any time to rotate the canary — every run produces a
# different key, so the value never sits fixed in a tracked file.
#
# Usage: ./generate-canary-secret.sh [--apply]
#   (no args)  print the generated Secret YAML to stdout
#   --apply    also kubectl apply it against the current context

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
eval "$("$SCRIPT_DIR/../shared/generate-canary-creds.sh")"

YAML=$(kubectl create secret generic canary-aws-creds \
  --namespace=floci-deception \
  --dry-run=client -o yaml \
  --from-literal=AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY" \
  --from-literal=AWS_DEFAULT_REGION=us-east-1 \
  --from-literal=credentials="[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY
region = us-east-1
")

ALERTS_FILE="$SCRIPT_DIR/canary-access-key-id.yaml"
kubectl create secret generic canary-access-key-id \
  --namespace=floci-deception-alerts \
  --dry-run=client -o yaml \
  --from-literal=CANARY_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" > "$ALERTS_FILE"

if [ "${1:-}" = "--apply" ]; then
  echo "$YAML" | kubectl apply -f -
  echo "canary rotated: $AWS_ACCESS_KEY_ID" >&2
else
  echo "$YAML"
fi

echo "" >&2
echo "discord-alert-tailer's canary-key filter needs $ALERTS_FILE applied too -- against the management-cluster context (a different cluster):" >&2
echo "  kubectl config use-context <management-cluster-context>" >&2
echo "  kubectl apply -f $ALERTS_FILE" >&2
