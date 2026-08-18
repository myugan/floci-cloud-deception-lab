#!/bin/sh
# Generates a fresh canary AWS access key + secret (real AWS format:
# AKIA-prefixed 20-char ID, 40-char base64 secret, both CSPRNG-random —
# no readable words baked in, unlike a hand-typed value) and applies it
# as the canary-aws-creds Secret in the floci-deception namespace.
#
# Run this any time to rotate the canary — every run produces a
# different key, so the value never sits fixed in a tracked file.
#
# Usage: ./generate-canary-secret.sh [--apply]
#   (no args)  print the generated Secret YAML to stdout
#   --apply    also kubectl apply it against the current context

set -eu

AKID_SUFFIX=""
while [ ${#AKID_SUFFIX} -lt 16 ]; do
  AKID_SUFFIX="${AKID_SUFFIX}$(openssl rand -base64 24 | tr -dc 'A-Z0-9')"
done
AKID="AKIA$(echo "$AKID_SUFFIX" | cut -c1-16)"
SECRET=$(openssl rand -base64 30)

YAML=$(kubectl create secret generic canary-aws-creds \
  --namespace=floci-deception \
  --dry-run=client -o yaml \
  --from-literal=AWS_ACCESS_KEY_ID="$AKID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$SECRET" \
  --from-literal=AWS_DEFAULT_REGION=us-east-1 \
  --from-literal=credentials="[default]
aws_access_key_id = $AKID
aws_secret_access_key = $SECRET
region = us-east-1
")

if [ "${1:-}" = "--apply" ]; then
  echo "$YAML" | kubectl apply -f -
  echo "canary rotated: $AKID" >&2
else
  echo "$YAML"
fi
