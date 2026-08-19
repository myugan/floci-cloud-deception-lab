#!/bin/sh
# Generates a fresh canary AWS access key + secret (real AWS format:
# AKIA-prefixed 20-char ID, 40-char base64 secret, both CSPRNG-random
# — no readable words baked in, unlike a hand-typed value). Prints
# AWS_ACCESS_KEY_ID=... and AWS_SECRET_ACCESS_KEY=... to stdout;
# nothing orchestrator-specific here. Both
# scripts/generate-canary-secret.sh (Kubernetes) and
# compose/scripts/generate-canary-secret.sh (Compose) eval this and
# apply the result their own way.

set -eu

AKID_SUFFIX=""
while [ ${#AKID_SUFFIX} -lt 16 ]; do
  AKID_SUFFIX="${AKID_SUFFIX}$(openssl rand -base64 24 | tr -dc 'A-Z0-9')"
done
AKID="AKIA$(echo "$AKID_SUFFIX" | cut -c1-16)"
SECRET=$(openssl rand -base64 30)

echo "AWS_ACCESS_KEY_ID=$AKID"
echo "AWS_SECRET_ACCESS_KEY=$SECRET"
