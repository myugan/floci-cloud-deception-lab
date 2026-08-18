#!/bin/sh
# Installs the Tailscale Kubernetes Operator into the CURRENT kubectl
# context — point this at timbernetes, not the management cluster.
#
# Mirrors how the management cluster already runs it (same chart
# version, 1.102.2) for consistency, but installed directly via `helm
# install` here rather than through Flux/HelmRelease — this repo's own
# convention has been direct kubectl/helm application throughout, and
# wiring this into timbernetes's existing Flux instance would mean
# knowing/matching whatever git source it's already configured to
# reconcile from, which isn't something we control from here.
#
# Requires OAUTH_CLIENT_ID / OAUTH_CLIENT_SECRET env vars set first —
# either the same OAuth client already used in the management cluster
# (kubectl -n tailscale get secret operator-oauth -o jsonpath='{.data}'
# on that cluster's context, base64-decoded), or a fresh client scoped
# to just this cluster. Same tailnet either way, since it's the same
# Tailscale account.

set -eu

: "${OAUTH_CLIENT_ID:?set OAUTH_CLIENT_ID first}"
: "${OAUTH_CLIENT_SECRET:?set OAUTH_CLIENT_SECRET first}"

kubectl apply -f 00-namespace.yaml

helm repo add tailscale https://pkgs.tailscale.com/helmcharts
helm repo update tailscale

helm upgrade --install tailscale-operator tailscale/tailscale-operator \
  --namespace tailscale \
  --version 1.102.2 \
  --set-string oauth.clientId="$OAUTH_CLIENT_ID" \
  --set-string oauth.clientSecret="$OAUTH_CLIENT_SECRET" \
  --set operatorConfig.hostname=floci-timbernetes-operator \
  --set-string proxyConfig.defaultTags=tag:k8s-operator \
  --wait

echo "operator installed — check: kubectl -n tailscale get pods"
