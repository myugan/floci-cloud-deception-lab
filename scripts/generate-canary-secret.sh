#!/bin/sh
# Thin Kubernetes wrapper around shared/generate-canary-creds.sh --
# applies the generated key as the canary-aws-creds Secret in the
# floci-deception namespace.
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

if [ "${1:-}" = "--apply" ]; then
  echo "$YAML" | kubectl apply -f -
  echo "canary rotated: $AWS_ACCESS_KEY_ID" >&2
else
  echo "$YAML"
fi
