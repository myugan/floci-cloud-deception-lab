#!/bin/sh
# Thin Kubernetes wrapper around shared/generate-certs.sh -- generates
# the CA + leaf keypair, then applies them as the honeypot-ca-cert /
# honeypot-tls-leaf Secrets. These are real private keys (unlike the
# canary AWS credential, which is *meant* to leak) — regenerate them
# with this script instead of committing them to git.
#
# Usage: ./generate-tls-secrets.sh [--apply]
#   (no args)  generate the keys/certs into a temp dir, print the path
#   --apply    also kubectl apply both Secrets against the current context

set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR=$(mktemp -d)

"$SCRIPT_DIR/../shared/generate-certs.sh" "$WORKDIR"
cd "$WORKDIR"

if [ "${1:-}" = "--apply" ]; then
  kubectl create secret generic honeypot-ca-cert \
    --namespace=floci-deception \
    --from-file=ca-bundle.pem=ca-cert.pem \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl create secret generic honeypot-tls-leaf \
    --namespace=floci-deception \
    --from-file=leaf-cert.pem=leaf-cert.pem \
    --from-file=leaf-key.pem=leaf-key.pem \
    --dry-run=client -o yaml | kubectl apply -f -

  echo "applied — restart the honeypot pod to pick up the new cert:" >&2
  echo "  kubectl -n floci-deception delete pod -l app=floci-deception" >&2
fi
