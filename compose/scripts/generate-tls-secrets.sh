#!/bin/sh
# Thin Compose wrapper around shared/generate-certs.sh -- writes the
# CA + leaf keypair to secrets/tls/, which docker-compose.yml bind-
# mounts into envoy and ml-worker.
#
# Usage: ./generate-tls-secrets.sh

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$SCRIPT_DIR/../secrets/tls"

"$SCRIPT_DIR/../../shared/generate-certs.sh" "$OUTDIR"

echo "certs written to $OUTDIR" >&2
echo "restart envoy to pick them up: docker compose restart envoy" >&2
