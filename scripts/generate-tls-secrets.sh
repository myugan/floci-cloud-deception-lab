#!/bin/sh
# Generates the CA + leaf TLS keypairs the envoy-sidecar uses to
# terminate intercepted AWS traffic, and applies them as the
# honeypot-ca-cert / honeypot-tls-leaf Secrets. These are real private
# keys (unlike the canary AWS credential, which is *meant* to leak) —
# regenerate them with this script instead of committing them to git.
#
# The leaf cert's SAN list covers every AWS region's regional and
# S3-virtual-hosted-style endpoints (*.<region>.amazonaws.com,
# *.s3.<region>.amazonaws.com, dualstack variants, ...) — without this
# breadth, real aws-cli/boto3 calls to regional or S3 endpoints fail
# TLS validation and the interception falls apart silently.
#
# Usage: ./generate-tls-secrets.sh [--apply]
#   (no args)  generate the keys/certs into a temp dir, print the path
#   --apply    also kubectl apply both Secrets against the current context

set -eu

WORKDIR=$(mktemp -d)
cd "$WORKDIR"

echo "generating CA..." >&2
# Subject/CN deliberately generic: this cert is mounted where a
# compromised decoy-app can read it, and `openssl x509 -subject` is
# the first thing anyone checking whether TLS is being intercepted
# would run. Anything honeypot-flavored here is a confession.
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout ca-key.pem -out ca-cert.pem \
  -subj "/O=Internal PKI/CN=Internal Root CA" >/dev/null 2>&1

echo "building SAN list (all AWS regions, incl. S3 virtual-hosted)..." >&2
python3 - > leaf.ext <<'PYEOF'
regions = """us-east-1 us-east-2 us-west-1 us-west-2 af-south-1 ap-east-1
ap-south-1 ap-south-2 ap-southeast-1 ap-southeast-2 ap-southeast-3
ap-southeast-4 ap-southeast-5 ap-northeast-1 ap-northeast-2 ap-northeast-3
ca-central-1 ca-west-1 eu-central-1 eu-central-2 eu-west-1 eu-west-2
eu-west-3 eu-north-1 eu-south-1 eu-south-2 me-south-1 me-central-1
sa-east-1 il-central-1""".split()

sans = ["DNS:*.amazonaws.com", "DNS:amazonaws.com",
        "DNS:*.s3.amazonaws.com", "DNS:s3.amazonaws.com"]
for r in regions:
    sans.append(f"DNS:*.{r}.amazonaws.com")
    sans.append(f"DNS:*.dualstack.{r}.amazonaws.com")
    sans.append(f"DNS:*.s3.{r}.amazonaws.com")
    sans.append(f"DNS:*.s3.dualstack.{r}.amazonaws.com")
    sans.append(f"DNS:*.s3-fips.{r}.amazonaws.com")
print("subjectAltName = " + ", ".join(sans))
PYEOF

echo "generating leaf cert, signed by the CA above..." >&2
openssl req -newkey rsa:2048 -nodes -keyout leaf-key.pem -out leaf.csr \
  -subj "/O=Internal PKI/CN=*.amazonaws.com" >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -days 825 -extfile leaf.ext -out leaf-cert.pem >/dev/null 2>&1

echo "generated in: $WORKDIR" >&2

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
