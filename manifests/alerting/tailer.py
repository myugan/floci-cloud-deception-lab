#!/usr/bin/env python3
"""
Tails Loki's real-time WebSocket API for {log_type="cloudtrail"} and posts
one Discord embed per event, as it arrives — no batching, no polling delay,
no firing/resolved lifecycle.

Severity coloring is purely a display concern here, not a Loki label
(kept out of the log data model per earlier feedback) — picks an embed
color from the action name so a busy channel is scannable at a glance.

Dedup guard: Envoy's Lua callback can fire more than once for the same
logical request, producing repeated identical eventIDs in the log. A
small recently-seen set drops repeats so one client call never posts as
multiple identical embeds.
"""
import json
import os
import re
import time
import urllib.parse
from collections import deque

import requests
import websocket

LOKI_WS = (
    "ws://loki.loki.svc.cluster.local:3100/loki/api/v1/tail?query="
    + urllib.parse.quote('{log_type="cloudtrail"}')
)
DISCORD_WEBHOOK = os.environ["DISCORD_WEBHOOK_URL"]

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

    fields = [
        {"name": "Service", "value": f"`{d.get('eventSource', '?')}`", "inline": True},
        {"name": "Action", "value": f"**{action}**", "inline": True},
        {"name": "Region", "value": f"`{d.get('awsRegion', '?')}`", "inline": True},
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
    try:
        r = requests.post(DISCORD_WEBHOOK, json=payload, timeout=10)
        print(f"posted to discord: status={r.status_code}", flush=True)
    except Exception as e:
        print(f"discord post failed: {e}", flush=True)

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

def on_message(ws, message):
    data = json.loads(message)
    for stream in data.get("streams", []):
        for _ts, line in stream.get("values", []):
            try:
                event = json.loads(line)
            except Exception:
                post_discord({"content": f"cloudtrail activity (unparsed): {line[:200]}"})
                continue
            if already_seen(event.get("requestID")):
                continue
            post_discord({"embeds": [format_embed(event)]})

def on_error(ws, error):
    print(f"ws error: {error}", flush=True)

def on_close(ws, *_a):
    print("ws closed", flush=True)

def on_open(ws):
    print(f"ws connected: {LOKI_WS}", flush=True)

def main():
    while True:
        ws = websocket.WebSocketApp(
            LOKI_WS,
            on_open=on_open,
            on_message=on_message,
            on_error=on_error,
            on_close=on_close,
        )
        ws.run_forever()
        print("reconnecting in 5s", flush=True)
        time.sleep(5)

if __name__ == "__main__":
    main()
