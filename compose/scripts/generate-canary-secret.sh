#!/bin/sh
# Thin Compose wrapper around shared/generate-canary-creds.sh --
# writes the canary key as both secrets/canary.env (env_file for
# envoy and ml-worker, and -- via the CANARY_ACCESS_KEY_ID line below
# -- for discord-alert-tailer, which only needs the ID to recognize
# "our canary" vs. some other credential) and secrets/credentials
# (bind-mounted as ml-worker's ~/.aws/credentials, realistic bait).
#
# Run this any time to rotate the canary — every run produces a
# different key, so the value never sits fixed in a tracked file.
#
# Usage: ./generate-canary-secret.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$SCRIPT_DIR/../secrets"
mkdir -p "$OUTDIR"

eval "$("$SCRIPT_DIR/../../shared/generate-canary-creds.sh")"

cat > "$OUTDIR/canary.env" <<EOF
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
AWS_DEFAULT_REGION=us-east-1
CANARY_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
EOF

cat > "$OUTDIR/credentials" <<EOF
[default]
aws_access_key_id = $AWS_ACCESS_KEY_ID
aws_secret_access_key = $AWS_SECRET_ACCESS_KEY
region = us-east-1
EOF

echo "canary rotated: $AWS_ACCESS_KEY_ID" >&2
echo "restart the stack to pick it up: docker compose restart" >&2
