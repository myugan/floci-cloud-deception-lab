"""
Shared core for posting CloudTrail-shaped events to Discord as they
happen -- one embed per event, no batching, no polling delay, no
firing/resolved lifecycle. Orchestrator-agnostic: this is the part
that's identical regardless of where the events come from.

Two different tailers import this:
  - manifests/alerting/tailer.py tails Loki's live websocket API.
  - compose's tailer (shared/file-tailer.py) tails the local log file
    directly, since Compose doesn't assume a Loki is available.
Only "how events arrive" differs between them; formatting, severity
coloring, retry-on-failure, and the dedup guard all live here once.

Severity coloring is purely a display concern here, not a log label
(kept out of the log data model per earlier feedback) — picks an
embed color from the action name so a busy channel is scannable at a
glance.

Dedup guard: Envoy's Lua callback can fire more than once for the
same logical request, producing repeated identical eventIDs in the
log. A small recently-seen set drops repeats so one client call never
posts as multiple identical embeds.
"""
import json
import os
import re
import time
from collections import deque

import requests

DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]
if not DISCORD_WEBHOOK:
    # Kubernetes leaves this genuinely unset if misconfigured (a clear
    # KeyError above). Compose's optional profile passes it through as
    # an empty string when .env isn't set, which would otherwise fail
    # opaquely inside requests.post() instead of here.
    raise RuntimeError("DISCORD_WEBHOOK_URL is empty -- set it in .env")

SEEN_MAX = 500

COLOR_CRITICAL = 0xE74C3C  # red    — privesc / persistence / destructive
COLOR_WARNING = 0xE67E22   # orange — general mutating calls
COLOR_INFO = 0x95A5A6      # grey   — recon / read-only, routine noise

# Purely for choosing a color — no labels, no Loki, nothing upstream.
_CRITICAL_RE = re.compile(
    r"^(Attach.*Policy|Put.*Policy|Detach.*Policy|.*PolicyVersion|AssumeRole.*|"
    r"CreateLoginProfile|UpdateLoginProfile|AddUserToGroup|UpdateAssumeRolePolicy|"
    r"CreateAccessKey|UpdateAccessKey|Delete.*|Terminate.*|Revoke.*)$"
)
_INFO_RE = re.compile(r"^(Get.*|List.*|Describe.*|Lookup.*)$")


def severity_color(event_name: str) -> int:
    if _CRITICAL_RE.match(event_name):
        return COLOR_CRITICAL
    if _INFO_RE.match(event_name):
        return COLOR_INFO
    return COLOR_WARNING


def _truncate(s: str, limit: int) -> str:
    return s if len(s) <= limit else s[: limit - 1] + "…"


def format_embed(d: dict) -> dict:
    ua = d.get("userAgent", "?")
    if len(ua) > 200:
        ua = ua[:200] + "…"

    action = d.get("eventName", "?")
    title = "🚨 Canary key triggered"

    # sourceIPAddress comes through as ip:port; the port's meaningless
    # here (always some ephemeral local port), just show the address.
    src_ip = d.get("sourceIPAddress", "?").rsplit(":", 1)[0]

    fields = [
        {"name": "Service", "value": f"`{d.get('eventSource', '?')}`", "inline": True},
        {"name": "Action", "value": f"**{action}**", "inline": True},
        {"name": "Region", "value": f"`{d.get('awsRegion', '?')}`", "inline": True},
        {"name": "Source IP", "value": f"`{src_ip}`", "inline": True},
    ]

    params = d.get("requestParameters")
    if params:
        params_str = _truncate(json.dumps(params), 1000)
        fields.append({"name": "Parameters", "value": f"```json\n{params_str}\n```", "inline": False})

    fields.append({"name": "User-Agent", "value": f"```{ua}```", "inline": False})

    return {
        "title": title,
        "color": severity_color(action),
        "fields": fields,
        "footer": {"text": "floci-deception"},
        "timestamp": d.get("eventTime"),
    }


def post_discord(payload: dict):
    for attempt in range(3):
        try:
            r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
            if r.status_code == 429:
                wait = r.json().get("retry_after", 1)
                time.sleep(wait)
                continue
            print(f"posted to discord: status={r.status_code}", flush=True)
            return
        except Exception as e:
            print(f"discord post failed (attempt {attempt + 1}/3): {e}", flush=True)
            time.sleep(2 ** attempt)
    print("discord post dropped after 3 attempts", flush=True)


_seen_ids = set()
_seen_order = deque()


def already_seen(event_id: str) -> bool:
    if not event_id:
        return False
    if event_id in _seen_ids:
        return True
    _seen_ids.add(event_id)
    _seen_order.append(event_id)
    if len(_seen_order) > SEEN_MAX:
        old = _seen_order.popleft()
        _seen_ids.discard(old)
    return False


def handle_line(line: str):
    """One log line in, zero or one Discord post out. Shared by both
    tailers so a malformed line or a duplicate event is handled
    identically regardless of transport.

    A malformed line means Envoy logged a connection where its own
    Lua filter never finished (TLS-only probes, truncated requests,
    scanners that connect and drop) -- x-ct-event-rest comes back as
    a literal "-", which isn't valid JSON. That's background internet
    scan noise on an exposed :443, not an attacker action worth a
    Discord ping -- print it to stdout (still visible in
    docker/kubectl logs) instead of paging."""
    try:
        event = json.loads(line)
    except Exception:
        print(f"cloudtrail activity (unparsed, not alerted): {line[:200]}", flush=True)
        return
    if already_seen(event.get("requestID")):
        return
    post_discord({"embeds": [format_embed(event)]})
