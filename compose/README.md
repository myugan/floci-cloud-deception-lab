# Compose deployment

Same honeypot as `../manifests/`, ported to plain Docker Compose for a single
droplet instead of a Kubernetes cluster. The actual security logic (Envoy's
interception + CloudTrail logging + IMDS emulation, the iptables redirect,
the fake IAM policy doc, the resource-seeding script) lives in `../shared/`
and is identical between both deployments — nothing here is a forked copy.

## Deploy

```sh
cd compose
./scripts/generate-tls-secrets.sh
./scripts/generate-canary-secret.sh
docker compose up -d
```

Ray takes 60-100s to start — the dashboard listens well before it's actually
ready to serve requests, so an early check can look broken when it's just
still warming up. Check: `docker compose ps`.

Verified against the real thing: `curl http://<droplet>:8265/` returns the
Ray dashboard, a job submitted through it that calls `boto3` picks up the
canary key from the environment and gets a real, correctly-shaped AWS
response back through the interception, and `docker compose logs envoy`
shows it CloudTrail-shaped with the right `eventName`.

Watch the CloudTrail-shaped log live, no Loki needed:

```sh
docker compose logs -f envoy
```

Ship it somewhere with promtail instead (edit `promtail.yaml`'s client URL
first):

```sh
docker compose --profile logging up -d
```

## Resource seeding

floci's storage is in-memory — every restart comes back completely empty
across every service, which is itself a tell: a real compromised AWS
account almost never looks this blank. The `floci-seed` container populates
a small, believable set of resources on startup (a few EC2 instances, three
S3 buckets, two IAM roles including the one the IMDS bait already implies,
one DynamoDB table), then sleeps forever. Runs against floci directly,
bypassing envoy, so none of it shows up in the CloudTrail-shaped log or
triggers a Discord alert.

EC2 instances specifically: floci auto-transitions every `RunInstances`
result to `terminated` within a few seconds regardless of parameters, and
won't allow `StartInstances` to undo it (matches real AWS's own
irreversible-termination rule) — that's floci's own behavior, not something
this fixes. `describe-instances` still shows full realistic detail instead
of an empty list; it just won't read as a currently-running fleet.

## One gotcha if you ever touch `docker-compose.yml`

`envoy` sets `ENVOY_UID: "0"`. The official image's own entrypoint drops
privileges to a non-root `envoy` user by default, which then can't read the
600-mode private key generated above — surfaces as a confusing "Failed to
load incomplete private key" rather than a permission error. Keeping envoy
root matches what the Kubernetes deployment already does; don't remove this
env var or "fix" it by loosening the key file's permissions instead.

## What's different from the Kubernetes deployment, and why

- **No Cilium-equivalent egress lockdown.** The k8s deployment uses a
  CiliumNetworkPolicy to hard-deny all egress except DNS and log shipping,
  enforced at the CNI layer regardless of what happens inside the container.
  A bare droplet has no CNI. If you need that here, it'd have to be
  iptables-based — not built yet, so treat this as less contained than the
  k8s version until it is.
- **No PID-namespace leak to worry about.** Compose doesn't share PID
  namespaces across services by default, so `ps aux` inside `ml-worker`
  never shows the other containers' process names to begin with — the exact
  leak `shareProcessNamespace: true` caused in the k8s version can't happen
  here, nothing to fix.
- **No `entrypoint.sh` / docker-facade equivalent.** Those existed
  specifically to hide Kubernetes-only artifacts (kubelet-injected
  `KUBERNETES_*` env vars, kubelet's managed `/etc/hosts` banner). None of
  that exists outside Kubernetes, so there's nothing to hide.
- **Rotating secrets doesn't hot-reload.** `docker compose restart` after
  running either generator script.

## Layout

```
compose/
├── docker-compose.yml
├── promtail.yaml            -- edit the client URL before enabling --profile logging
├── scripts/
│   ├── generate-tls-secrets.sh
│   └── generate-canary-secret.sh
└── secrets/                 -- gitignored, created by the scripts above
```
