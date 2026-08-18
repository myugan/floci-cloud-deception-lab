# floci-cloud-deception-lab

AWS honeypot built on [floci](https://floci.io/aws/) (an AWS API emulator).
The bait is a real, currently-exploited vulnerability (not a toy) — an
attacker who gets RCE and finds the canary credential, then calls real AWS
endpoints with **no `--endpoint-url` override**, gets transparently
redirected to floci instead. Every call is logged in a CloudTrail-shaped
format, queryable via LogQL, and pushed to Discord as it happens.

**Status: live and publicly reachable** at
`https://ml-compute-01.tail6c68d0.ts.net` (Tailscale Funnel — see
[Expose it publicly](#expose-it-publicly-tailscale-funnel)). Verified
end to end, including submitting the exploit from an external client
with zero tailnet membership.

## The bait: Ray, CVE-class "ShadowRay" (CVE-2025-62593 / CVE-2023-48022)

`decoy-app` runs `rayproject/ray:2.9.0-py311` (fixed in 2.52.0 — this pin
is deliberate). Ray's job-submission dashboard API has no real
authentication by design: a single unauthenticated request submits a job
whose `entrypoint` is a raw shell command, executed on the head node.

```sh
curl -X POST http://<target>:8265/api/jobs/ \
  -H 'Content-Type: application/json' \
  -d '{"entrypoint": "id; env | grep AWS_", "runtime_env": {}}'
```

Verified end-to-end against this deployment: the exploit reads the canary
credential from the environment, calls `boto3.client("sts")` /
`boto3.client("iam")` with zero endpoint override, and the response comes
back with `"server": "envoy"` in the metadata — proof it transparently hit
our interception stack, not real AWS. See `manifests/honeypot/04-deployment.yaml`
for the full container spec and why this replaced an earlier Langflow pick
(CVE-2026-9198's exploit needed an undocumented lambda/generator payload
shape that wasn't worth the fragility).

Thematically apt, not contrived: Ray clusters routinely hold cloud
credentials for autoscaling compute — "attacker RCEs an ML training
cluster and finds cloud creds in its environment" is the real ShadowRay
campaigns' actual pattern.

## Layout — two different clusters

This repo spans **two Kubernetes clusters**. Keep that straight or you'll
`kubectl apply` the wrong thing against the wrong context.

```
manifests/
├── honeypot/    -> the "timbernetes" cluster (Cluster API-managed)
│                   the decoy pod itself: Ray (the bait), floci, the
│                   TLS-intercepting sidecar, the iptables redirect,
│                   the network lockdown
└── alerting/    -> the management cluster (where Loki/Grafana live)
                    tails Loki in real time, posts one Discord message
                    per event — deliberately NOT run inside the honeypot
                    pod, so alerting has zero attack-surface impact on it
```

**`timbernetes` is the cluster this honeypot is deployed on — it is not
a dedicated honeypot cluster.** It also runs `flux-system` and
`fluent-bit` today, and is a normal Cluster API-managed cluster someone
could reasonably add more workloads to later. That matters because this
pod is now genuinely, publicly exploitable and actively targeted by
real internet scanners — the isolation this design relies on
(`CiliumNetworkPolicy` default-deny egress scoped to `app:
floci-deception`, non-root everywhere, no ServiceAccount token, no
K8s API reachability) only protects *this* workload. It does not
automatically extend to anything else added to the cluster later.

**If more workloads ever run on `timbernetes` alongside this honeypot,
they need their own equivalent hardening** — their own default-deny
NetworkPolicy, no shared ServiceAccounts with the honeypot namespace,
no assumption that "the cluster is locked down" covers them too. Each
namespace's isolation here is deliberate and per-workload, not a
cluster-wide property. Treat `timbernetes` as "hosts a publicly
exploited target" when deciding what else belongs on it.

### Deploy the honeypot (timbernetes)

Run these **in order** — the two scripts create secrets the Deployment
in step 3 mounts, so running step 3 first just means the pod sits
waiting until the secrets show up:

```sh
kubectl config use-context <timbernetes-context>

# 1. TLS keys for intercepting AWS traffic (real private keys — never
#    committed, see "Secrets" below)
./scripts/generate-tls-secrets.sh --apply

# 2. Canary AWS credential (also never committed — regenerates fresh
#    every run)
./scripts/generate-canary-secret.sh --apply

# 3. Everything else: namespace, floci, envoy, iptables redirect,
#    network lockdown, the Ray decoy itself
kubectl apply -f manifests/honeypot/
```

Ray takes ~60-100s to fully start (image pull + cluster bootstrap). Check
readiness with `kubectl -n floci-deception get pods` and confirm the
dashboard responds: `curl http://<pod-ip>:8265/`.

### Expose it publicly (Tailscale Funnel)

**Live at `https://ml-compute-01.tail6c68d0.ts.net`** — genuinely public,
verified by submitting the exploit from an external client with zero
tailnet membership (see [The bait](#the-bait-ray-cve-class-shadowray-cve-2025-62593--cve-2023-48022)
above). This will attract real scanning traffic — CVE-2025-62593's
underlying issue is actively mass-exploited (CISA KEV, RondoDox botnet).

Setup, if reproducing or redeploying elsewhere:

```sh
kubectl config use-context <timbernetes-context>
export OAUTH_CLIENT_ID=...      # from Tailscale admin console, or reuse
export OAUTH_CLIENT_SECRET=...  # an existing operator's client (same tailnet)
cd manifests/honeypot/tailscale-operator
./install.sh
kubectl apply -f ../06-ray-dashboard-service.yaml
kubectl apply -f ../07-ray-funnel-ingress.yaml
```

**Prerequisites on the Tailscale side** (admin console → Access Controls,
not visible or settable from kubectl):
- HTTPS Certificates enabled for the tailnet
- Funnel granted via `nodeAttrs` to whatever tag the OAuth client
  provisions with — this setup uses `tag:k8s-operator` (see gotcha below)

**Two gotchas hit during setup, worth knowing before repeating this:**

1. **The Helm chart's proxy tag default doesn't match the OAuth client's
   permission.** `operatorConfig.defaultTags` (the tag the *operator
   itself* gets) already defaults to `tag:k8s-operator` — but the
   *separate* `proxyConfig.defaultTags` (the tag each **provisioned
   proxy** gets, e.g. the one backing this Ingress) defaults to plain
   `tag:k8s`, which this OAuth client isn't permitted to use. Symptom:
   the Ingress sits with no `ADDRESS` forever, operator logs show
   `requested tags [tag:k8s] are invalid or not permitted (400)` on
   loop. Fix (already in `install.sh`):
   `--set-string proxyConfig.defaultTags=tag:k8s-operator`.
2. **DNS propagation lag on first creation.** Once the proxy pod
   (`ts-ray-dashboard-funnel-*`) is `Running` and the Ingress reports
   `ADDRESS`, the hostname can still `NXDOMAIN` for roughly a minute
   before it resolves — this is normal, not a misconfiguration. An
   already-established hostname (like Loki's) resolves instantly by
   comparison; only brand-new ones have this delay.

`timbernetes` had zero prior Tailscale presence (unlike the management
cluster, where Loki/Grafana already piggyback on an existing operator) —
this installs a **second, independent** operator instance there, reusing
the same OAuth client/tailnet. `/dev/net/tun` was confirmed present on
the Incus-backed nodes beforehand, so this runs with real TUN networking,
not the userspace fallback.

### Deploy alerting (management cluster)

Same idea — set the webhook secret first, then apply the rest:

```sh
kubectl config use-context <management-cluster-context>

# 1. Your Discord webhook URL (never written to a file — see "Secrets" below)
./scripts/set-discord-webhook.sh 'https://discord.com/api/webhooks/...'

# 2. Everything else: namespace, the tailer Deployment
kubectl apply -f manifests/alerting/
```

Get a webhook URL from Discord: Server Settings → Integrations →
Webhooks → New Webhook → Copy Webhook URL.

Alerts are batched over a 3s window (a lone event still gets a full
detailed embed; a burst of several collapses into one summary — real
attacker tooling like Pacu/enumerate-iam fires dozens of calls in
seconds, and posting one Discord message per line would flood the
channel) and color-coded by severity (red = privesc/persistence/
destructive-shaped action, orange = general mutation, grey = recon).

## Secrets — none of these are committed

Three pieces of real secret material this repo needs, none of them
tracked in git (`.gitignore` excludes all three generated files) — each
has a script that generates and applies it fresh instead:

| Secret | Script | Why it's not committed |
|---|---|---|
| TLS interception keys | `scripts/generate-tls-secrets.sh --apply` | Real private keys — regenerating is cheap, committing them isn't necessary |
| Canary AWS credential | `scripts/generate-canary-secret.sh --apply` | Not sensitive by design (it's *meant* to leak), but committing a fixed value defeats rotating it |
| Discord webhook URL | `scripts/set-discord-webhook.sh <url>` | Applied directly as a Secret — never touches a file at all, so there's nothing to accidentally commit |

Run each any time to rotate. The [deploy steps above](#deploy-the-honeypot-timbernetes)
already call these in the right order — this table is just the reference
if you need to rotate one later without redeploying everything.

## Scope — read this before relying on it as a "canary token"

**This setup only sees activity that happens from *inside* the `decoy-app`
container's own network namespace.** The interception mechanism (iptables
`REDIRECT` + Envoy TLS termination) is scoped to one pod's netns — it does
not, and cannot, catch the credential being used from anywhere else.

This means it fits one specific scenario: an attacker gets RCE into
`decoy-app` itself (via the Ray exploit above) and runs `aws`/SDK calls
from that shell. It does **not** fit the more common "canary token" idea
of leaking a key somewhere public (a GitHub commit, a Slack paste, a
config file) and getting alerted the moment *anyone, anywhere* uses it —
a key leaked that way gets used from the attacker's own network, which
never touches this pod, so nothing here would ever fire.

If the goal is that broader, leak-and-wait style detection, this needs a
different mechanism entirely — a real (but locked-down) AWS credential
monitored by GuardDuty/CloudTrail in an actual AWS account, or a hosted
service like [canarytokens.org](https://canarytokens.org). This repo solves
a narrower, complementary problem: observing what an attacker does *after*
they've already compromised this specific decoy workload.

## CloudTrail-shaped logging

Every intercepted AWS call is logged as a real CloudTrail-style record
(`eventSource`, `eventName`, `userIdentity`, `awsRegion`, `sourceIPAddress`,
`userAgent`, `requestParameters`) — built in an Envoy Lua filter, not
floci itself (floci's own `CloudTrailLogWriter`/`lookup-events` API was
tested and found non-functional: always returns empty, even after real
write actions past its flush interval).

Action-name resolution covers all three AWS protocol shapes floci's ~90
services use: query-protocol (STS/IAM/EC2 — `Action=X` in the POST body),
JSON-protocol (DynamoDB/Lambda — `X-Amz-Target` header), and REST-shaped
(S3 — inferred from method + bucket/key presence + subresource query
params like `?acl`/`?policy`, matching how real CloudTrail derives S3
event names).

Shipped via a `promtail` sidecar to the cluster's existing Loki (bridged
over Tailscale), tagged `log_type=cloudtrail` — query everything with
`{log_type="cloudtrail"}`, drill into any field with `| json`.

## Known gaps

- The Tailscale Operator install in `timbernetes` reuses the **same**
  OAuth client credential as the management cluster's operator (`tag:
  k8s-operator`, same permission scope in both places) rather than a
  credential scoped to just this cluster. If `timbernetes` is ever
  compromised beyond the honeypot pod itself, that credential — and by
  extension the management cluster's own Tailscale automation — is
  exposed too. A dedicated OAuth client per cluster would isolate that,
  not done here since the existing one was reused by choice.
- gVisor/sandboxing for `decoy-app` was deliberately not done — it needs
  node-level containerd changes on `timbernetes`, which also hosts
  unrelated workloads, so the blast radius was judged not worth it here.
- Structural Kubernetes tells that can't be fixed from a pod manifest:
  `/proc/*/cgroup` (`kubepods.slice`/`cri-containerd-*`), `/proc/mounts`
  source paths (`/var/lib/kubelet/...`), and the real pod-CIDR address on
  `ip addr`. Fixing these needs node/runtime-level changes or a real
  separate Docker host.
- floci's own storage is memory-only — a pod restart wipes every emulated
  AWS resource it created (buckets, users, keys, ...). The activity *log*
  (Loki/Discord) is independent of this and survives restarts fine —
  accepted as-is, not planned to change.
