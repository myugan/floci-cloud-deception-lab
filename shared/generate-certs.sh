#!/bin/sh
# Generates the CA + leaf TLS keypairs envoy uses to terminate
# intercepted AWS traffic. Orchestrator-agnostic: writes plain files
# to a directory, nothing k8s- or Compose-specific here. Both
# scripts/generate-tls-secrets.sh (Kubernetes) and
# compose/scripts/generate-tls-secrets.sh (Compose) call this and
# handle applying the result their own way.
#
# The leaf cert's SAN list covers every AWS region's regional and
# S3-virtual-hosted-style endpoints, plus the handful of services
# (ecr, pricing, iot-data) whose real endpoint hostname has more than
# one label before <region>.amazonaws.com and so isn't covered by the
# single-level wildcard — confirmed against real botocore endpoint
# resolution (client.meta.endpoint_url), not guessed. Without this
# breadth, real aws-cli/boto3 calls fail TLS validation and the
# interception falls apart silently.
#
# Usage: ./generate-certs.sh <output-dir>

set -eu

OUTDIR="${1:?usage: generate-certs.sh <output-dir>}"
mkdir -p "$OUTDIR"
cd "$OUTDIR"

echo "generating CA..." >&2
# Subject/CN deliberately generic: this cert is mounted where a
# compromised workload can read it, and `openssl x509 -subject` is
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
    sans.append(f"DNS:api.ecr.{r}.amazonaws.com")
    sans.append(f"DNS:api.pricing.{r}.amazonaws.com")
    sans.append(f"DNS:data-ats.iot.{r}.amazonaws.com")
print("subjectAltName = " + ", ".join(sans))
PYEOF

echo "generating leaf cert, signed by the CA above..." >&2
openssl req -newkey rsa:2048 -nodes -keyout leaf-key.pem -out leaf.csr \
  -subj "/O=Internal PKI/CN=*.amazonaws.com" >/dev/null 2>&1
openssl x509 -req -in leaf.csr -CA ca-cert.pem -CAkey ca-key.pem \
  -CAcreateserial -days 825 -extfile leaf.ext -out leaf-cert.pem >/dev/null 2>&1

echo "generated in: $OUTDIR" >&2
